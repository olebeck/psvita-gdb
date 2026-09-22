use core::ffi::c_void;
use core::panic;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicI32, Ordering};

use gdbstub::target::ext::breakpoints::WatchKind;
use vitasdk_sys::{
    SCE_EXCP_DABT, SCE_EXCP_PABT, SCE_EXCP_UNDEF_INSTRUCTION,
    SCE_EXCPMGR_EXCEPTION_HANDLING_CODE_2, SCE_EXCPMGR_EXCEPTION_NOT_HANDLED, SceExcpHandlingCode,
    SceExcpmgrExceptionContext, SceProcEventHandler, SceProcEventInvokeParam1,
    SceProcEventInvokeParam2, SceSysrootProcessHandler, SceUID,
    ksceKernelChangeThreadSuspendStatus, ksceKernelCreateEventFlag,
    ksceKernelRegisterProcEventHandler, ksceKernelRegisterSysEventHandler, ksceKernelSetEventFlag,
    ksceKernelSysrootSetProcessHandler,
};

use crate::cp14::enable_debug;
use crate::gdb::sessions::{
    EV_PROCESS_STARTED, ExceptionEvent, ExceptionKind, find_session_for_pid,
};
use crate::kernel::utils::PROCESS_HALT_STATUS;
use crate::kernel::{
    ffi::{ksceExcpmgrRegisterHandler, ksceKernelCopyFromUserProc, ksceKernelSuspendProcess},
    utils::get_thread_context_info,
};
use crate::{println, sce_call};

fn halt_for_debug(pid: SceUID, tid: SceUID) {
    unsafe { ksceKernelChangeThreadSuspendStatus(tid, 0x1002) };
    unsafe { ksceKernelSuspendProcess(pid, PROCESS_HALT_STATUS) };
}

const fn dfsr_is_write(dfsr: u32) -> bool {
    dfsr & (1 << 11) != 0
}

fn is_bkpt(insn: &[u8; 4], thumb: bool) -> bool {
    let word = u32::from_le_bytes(*insn);
    if thumb {
        (word as u16) & 0xff00 == 0xbe00
    } else {
        word & 0x0ff0_00f0 == 0x0120_0070
    }
}

fn fsr_is_debug(fsr: u32) -> bool {
    (((fsr & 0x400) >> 6) | (fsr & 0xF)) == 0x2
}

fn is_thumb(ctx: &SceExcpmgrExceptionContext) -> bool {
    (ctx.CPACR >> 5) & 1 != 0
}

#[macro_export]
macro_rules! excp_handler {
    ($name:ident, $handler:ident) => {
        unsafe extern "C" {
            fn $name(
                context: *mut ::vitasdk_sys::SceExcpmgrExceptionContext,
                code: ::vitasdk_sys::SceExcpHandlingCode,
            ) -> ::vitasdk_sys::SceExcpHandlingCode;
        }
        ::core::arch::global_asm!(
            ".arm",
            concat!(".global ", stringify!($name)),
            concat!(stringify!($name), ":"),
            ".word 0x0",                             // next handler pointer
            ".word 0x0",                             // prev handler pointer
            "mov r4, r0",                            // preserve context
            "cpsie i",                               // enable irq
            concat!("blx ", stringify!($handler)),   // jump to handler
            "cpsid i",                               // disable irq
            "mov r1, r0",                            // arg0 = code
            "mov r0, r4",                            // arg1 = context
            concat!("ldr r2, =", stringify!($name)), // jump to next handler in the chain
            "ldr r2, [r2]",
            "add r2, r2, #8",
            "mov pc, r2"
        );
    };
}

excp_handler!(_gdb_pabt_handler, gdb_pabt_handler);
excp_handler!(_gdb_dabt_handler, gdb_dabt_handler);
excp_handler!(_gdb_undef_handler, gdb_undef_handler);

pub fn register_exception_handlers() {
    if let Err(err) = sce_call!(ksceExcpmgrRegisterHandler(
        SCE_EXCP_PABT,
        5,
        _gdb_pabt_handler
    )) {
        println!("{err} excp=SCE_EXCP_PABT");
    }
    if let Err(err) = sce_call!(ksceExcpmgrRegisterHandler(
        SCE_EXCP_DABT,
        5,
        _gdb_dabt_handler
    )) {
        println!("{err} excp=SCE_EXCP_DABT");
    }
    if let Err(err) = sce_call!(ksceExcpmgrRegisterHandler(
        SCE_EXCP_UNDEF_INSTRUCTION,
        5,
        _gdb_undef_handler
    )) {
        println!("{err} excp=SCE_EXCP_UNDEF_INSTRUCTION");
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gdb_pabt_handler(
    context: *const SceExcpmgrExceptionContext,
    code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    handle_prefetch_abort(unsafe { &*context }, code)
}

#[unsafe(no_mangle)]
pub extern "C" fn gdb_dabt_handler(
    context: *const SceExcpmgrExceptionContext,
    code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    handle_data_abort(unsafe { &*context }, code)
}

#[unsafe(no_mangle)]
pub extern "C" fn gdb_undef_handler(
    context: *const SceExcpmgrExceptionContext,
    code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    handle_undef(unsafe { &*context }, code)
}

fn handle_prefetch_abort(
    context: &SceExcpmgrExceptionContext,
    code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    println!("handle_prefetch_abort");
    if fsr_is_debug(context.IFSR) {
        return handle_break(context, code);
    }
    handle_exception(context, ExceptionKind::Pabt, context.IFAR)
}

fn handle_data_abort(
    context: &SceExcpmgrExceptionContext,
    code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    println!("handle_data_abort");
    if fsr_is_debug(context.DFSR) {
        return handle_watch(context, code);
    }
    handle_exception(context, ExceptionKind::Dabt, context.DFAR)
}

fn handle_undef(
    context: &SceExcpmgrExceptionContext,
    _code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    println!("handle_undef");
    handle_exception(context, ExceptionKind::Undef, 0)
}

fn handle_watch(
    context: &SceExcpmgrExceptionContext,
    _code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    let (pid, tid) = get_thread_context_info();
    let Some(session) = find_session_for_pid(pid) else {
        return SCE_EXCPMGR_EXCEPTION_NOT_HANDLED;
    };
    if !session.has_watchpoint(context.DFAR) {
        println!(
            "handle_watch: no armed watchpoint for DFAR=0x{:x}",
            context.DFAR
        );
        return SCE_EXCPMGR_EXCEPTION_NOT_HANDLED;
    }
    let kind = if dfsr_is_write(context.DFSR) {
        WatchKind::Write
    } else {
        WatchKind::Read
    };

    halt_for_debug(pid, tid);
    session.push_excp(ExceptionEvent::Watch {
        tid,
        addr: context.DFAR,
        kind,
    });
    SCE_EXCPMGR_EXCEPTION_HANDLING_CODE_2
}

fn handle_break(
    context: &SceExcpmgrExceptionContext,
    _code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    let fault_addr = context.address_of_faulting_instruction;
    let (pid, tid) = get_thread_context_info();
    println!(
        "handle_break tid={} ifsr={:x} ifar={:x} fault_addr={:x}",
        tid, context.IFSR, context.IFAR, fault_addr
    );

    let Some(session) = find_session_for_pid(pid) else {
        println!("no session for pid={pid}");
        return SCE_EXCPMGR_EXCEPTION_NOT_HANDLED;
    };

    let mut insn = [0u8; 4];
    if let Err(err) = sce_call!(ksceKernelCopyFromUserProc(
        pid,
        insn.as_mut_ptr() as _,
        fault_addr as _,
        insn.len()
    )) {
        println!("handle_break: {err}");
        return SCE_EXCPMGR_EXCEPTION_NOT_HANDLED;
    }
    halt_for_debug(pid, tid);

    if session.is_step(fault_addr) {
        session.step_finished();
    } else if is_bkpt(&insn, is_thumb(context)) {
        session.push_excp(ExceptionEvent::SwBreak { tid });
    } else {
        session.push_excp(ExceptionEvent::HwBreak { tid });
    };
    SCE_EXCPMGR_EXCEPTION_HANDLING_CODE_2
}

fn handle_exception(
    context: &SceExcpmgrExceptionContext,
    kind: ExceptionKind,
    addr: u32,
) -> SceExcpHandlingCode {
    let (pid, tid) = get_thread_context_info();
    println!(
        "handle_exception pid={pid} tid={tid} excp={kind:?} addr={addr:x} ifsr={:x} dfsr={:x}",
        context.IFSR, context.DFSR
    );
    let Some(session) = find_session_for_pid(pid) else {
        return SCE_EXCPMGR_EXCEPTION_NOT_HANDLED;
    };

    halt_for_debug(pid, tid);
    session.push_excp(ExceptionEvent::Exception { tid, kind });
    SCE_EXCPMGR_EXCEPTION_HANDLING_CODE_2
}

unsafe extern "C" fn handler_dummy_exit(_pid: SceUID, _flags: i32, _time: u64) {}

unsafe extern "C" fn handler_dummy_kill(_pid: SceUID) {}

unsafe extern "C" fn handler_dummy_modid(_pid: SceUID, _modid: SceUID, _time: u64) {}

unsafe extern "C" fn handler_dummy_modid_flag(
    _pid: SceUID,
    _modid: SceUID,
    _flags: i32,
    _time: u64,
) {
}

unsafe extern "C" fn handler_dummy_process_created(_a1: i32, _a2: i32, _a3: i32) -> i32 {
    0
}

static PROC_HANDLER: SceSysrootProcessHandler = SceSysrootProcessHandler {
    size: size_of::<SceSysrootProcessHandler>() as u32,
    unk_4: Some(handler_dummy_modid_flag),
    exit: Some(handler_dummy_exit),
    kill: Some(handler_dummy_kill),
    unk_10: Some(handler_dummy_modid),
    unk_14: Some(handler_dummy_modid),
    unk_18: Some(handler_dummy_modid),
    on_process_created: Some(handler_dummy_process_created),
    unk_20: Some(handler_dummy_modid),
    unk_24: Some(handler_dummy_modid_flag),
};

unsafe extern "C" fn handle_proc_create(
    pid: SceUID,
    _a2: *mut SceProcEventInvokeParam2,
    _a3: i32,
) -> i32 {
    //println!("handle_proc_create pid={pid}");
    if let Some(session) = find_session_for_pid(pid) {
        if let Some(evflag) = session.evflag() {
            if let Err(err) = evflag.set(EV_PROCESS_STARTED) {
                println!("handle_proc_create: {err}")
            }
        }
    }
    0
}

unsafe extern "C" fn handle_proc_kill(
    pid: SceUID,
    _a2: *mut SceProcEventInvokeParam1,
    _a3: i32,
) -> i32 {
    //println!("handle_proc_exit pid={pid}");
    if let Some(session) = find_session_for_pid(pid) {
        session.push_exited();
    }
    0
}

static PROC_HANDLER2: SceProcEventHandler = SceProcEventHandler {
    size: size_of::<SceProcEventHandler>() as u32,
    create: Some(handle_proc_create),
    exit: None,
    kill: Some(handle_proc_kill),
    stop: None,
    start: None,
    switch_process: None,
};

pub fn register_process_handlers() {
    if let Err(err) = sce_call!(ksceKernelSysrootSetProcessHandler(&PROC_HANDLER)) {
        panic!("{err}");
    }
    if let Err(err) = sce_call!(ksceKernelRegisterProcEventHandler(
        c"gdb_proc_event".as_ptr(),
        &PROC_HANDLER2,
        0
    )) {
        panic!("{err}");
    }
}

unsafe extern "C" fn handle_sysevent(
    resume: i32,
    eventid: i32,
    _args: *mut c_void,
    _opt: *mut c_void,
) -> i32 {
    if resume != 0 && eventid == 0x100000 {
        if let Err(err) = enable_debug() {
            println!("enable_debug: {err}");
        }
    }
    0
}

pub fn register_sysevent_handler() {
    if let Err(err) = sce_call!(ksceKernelRegisterSysEventHandler(
        c"enable_debug".as_ptr(),
        Some(handle_sysevent),
        null_mut()
    )) {
        panic!("register_sysevent_handlers: {err}");
    }
}
