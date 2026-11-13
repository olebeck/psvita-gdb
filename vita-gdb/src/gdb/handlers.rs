use core::ffi::c_void;
use core::ptr::null_mut;

use gdbstub::target::ext::breakpoints::WatchKind;
use vitasdk_sys::{
    SCE_EXCP_DABT, SCE_EXCP_PABT, SCE_EXCP_UNDEF_INSTRUCTION,
    SCE_EXCPMGR_EXCEPTION_HANDLING_CODE_2, SCE_EXCPMGR_EXCEPTION_NOT_HANDLED, SceExcpHandlingCode,
    SceExcpmgrExceptionContext, SceUID, ksceKernelChangeThreadSuspendStatus,
    ksceKernelRegisterSysEventHandler,
};

use crate::cp14::enable_debug;
use crate::gdb::exception_report;
use crate::gdb::sessions::{ExceptionEvent, ExceptionKind, ModuleEvent, find_session_for_pid};
use crate::kernel::ffi::{SysrootDbgpHandler, ksceKernelSysrootRegisterDbgpHandler};
use crate::kernel::utils::{PROCESS_HALT_STATUS, SceError, read_user_process};
use crate::kernel::{
    ffi::{ksceExcpmgrRegisterHandler, ksceKernelSuspendProcess},
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
    (ctx.SPSR >> 5) & 1 != 0
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
    if fsr_is_debug(context.IFSR) {
        return handle_break(context, code);
    }
    handle_exception(context, ExceptionKind::Pabt, context.IFAR)
}

fn handle_data_abort(
    context: &SceExcpmgrExceptionContext,
    code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    if fsr_is_debug(context.DFSR) {
        return handle_watch(context, code);
    }
    handle_exception(context, ExceptionKind::Dabt, context.DFAR)
}

fn handle_undef(
    context: &SceExcpmgrExceptionContext,
    _code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    handle_exception(context, ExceptionKind::Undef, 0)
}

fn handle_watch(
    context: &SceExcpmgrExceptionContext,
    _code: SceExcpHandlingCode,
) -> SceExcpHandlingCode {
    let (pid, tid) = get_thread_context_info();
    let write = dfsr_is_write(context.DFSR);
    exception_report::report_watch(context, pid, tid, write);

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
    let kind = if write {
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
    if false {
        exception_report::report_break(context, pid, tid);
    }

    let Some(session) = find_session_for_pid(pid) else {
        println!("no session for pid={pid}");
        return SCE_EXCPMGR_EXCEPTION_NOT_HANDLED;
    };

    let thumb = is_thumb(context);
    let read_len = if thumb { 2 } else { 4 };
    let mut insn = [0u8; 4];
    let Some(buf) = insn.get_mut(..read_len) else {
        return SCE_EXCPMGR_EXCEPTION_NOT_HANDLED;
    };
    if let Err(err) = read_user_process(pid, fault_addr as _, buf) {
        println!("handle_break: {err}");
        return SCE_EXCPMGR_EXCEPTION_NOT_HANDLED;
    }
    halt_for_debug(pid, tid);

    if session.is_step(tid, fault_addr) {
        session.step_finished();
    } else if is_bkpt(&insn, thumb) {
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
    exception_report::report_exception(context, pid, tid, kind, addr);

    let Some(session) = find_session_for_pid(pid) else {
        return SCE_EXCPMGR_EXCEPTION_NOT_HANDLED;
    };

    halt_for_debug(pid, tid);
    session.push_excp(ExceptionEvent::Exception { tid, kind });
    SCE_EXCPMGR_EXCEPTION_HANDLING_CODE_2
}

const DBGP_ERROR_INVALID_ARGUMENT: i32 = 0x8008_0001u32 as i32;

unsafe extern "C" fn handle_process_start(_parent_pid: SceUID, _pid: SceUID, _time: u64) -> i32 {
    0
}

unsafe extern "C" fn handle_process_exit(pid: SceUID, _exit_status: i32, _time: u64) -> i32 {
    if let Some(session) = find_session_for_pid(pid) {
        session.push_exited();
    }
    0
}

unsafe extern "C" fn handle_process_kill(pid: SceUID, _time: u64) -> i32 {
    if let Some(session) = find_session_for_pid(pid) {
        session.push_exited();
    }
    0
}

unsafe extern "C" fn handle_process_spontaneous_exit(
    _pid: SceUID,
    _status: u32,
    _time: u64,
) -> i32 {
    0
}

unsafe extern "C" fn handle_process_exit_to_spawn(
    _pid: SceUID,
    _spawn_pid: SceUID,
    _time: u64,
) -> i32 {
    0
}

unsafe extern "C" fn handle_exit_spawn(
    _pid: SceUID,
    _spawn_pid: SceUID,
    _prev_pid: SceUID,
    _time: u64,
) -> i32 {
    0
}

unsafe extern "C" fn handle_process_suspend(_pid: SceUID) -> i32 {
    0
}

unsafe extern "C" fn handle_process_resume(_pid: SceUID) -> i32 {
    0
}

unsafe extern "C" fn handle_app_abort(_pid: SceUID) -> i32 {
    0
}

unsafe extern "C" fn handle_module_start(pid: SceUID, modid: SceUID, _time: u64) -> i32 {
    if let Some(session) = find_session_for_pid(pid) {
        session.push_module(ModuleEvent::Start { modid });
    }
    0
}

unsafe extern "C" fn handle_module_stop(pid: SceUID, modid: SceUID, _time: u64) -> i32 {
    if let Some(session) = find_session_for_pid(pid) {
        session.push_module(ModuleEvent::Stop { modid });
    }
    0
}

unsafe extern "C" fn handle_is_debug_target(pid: SceUID) -> i32 {
    i32::from(find_session_for_pid(pid).is_some())
}

unsafe extern "C" fn handle_is_ps_button_captured() -> i32 {
    0
}

unsafe extern "C" fn handle_get_original_opcode(
    pid: SceUID,
    address: *mut c_void,
    opcode: *mut u32,
) -> i32 {
    if opcode.is_null() {
        return DBGP_ERROR_INVALID_ARGUMENT;
    }
    let Some(session) = find_session_for_pid(pid) else {
        return DBGP_ERROR_INVALID_ARGUMENT;
    };
    let Some(value) = session.get_original_opcode(address as u32) else {
        return DBGP_ERROR_INVALID_ARGUMENT;
    };
    unsafe { *opcode = value };
    0
}

unsafe extern "C" fn handle_code_modified(pid: SceUID, address: u32, instruction: u32) -> i32 {
    let Some(session) = find_session_for_pid(pid) else {
        return DBGP_ERROR_INVALID_ARGUMENT;
    };
    if session.set_original_opcode(address, instruction) {
        0
    } else {
        DBGP_ERROR_INVALID_ARGUMENT
    }
}

unsafe extern "C" fn handle_get_prx_debug_flag(pid: SceUID, flag: *mut u32) -> i32 {
    if flag.is_null() || find_session_for_pid(pid).is_none() {
        return DBGP_ERROR_INVALID_ARGUMENT;
    }
    unsafe { *flag = 0 };
    0
}

unsafe extern "C" fn handle_suspend_process_and_wait_resume(
    pid: SceUID,
    _modid: SceUID,
    _stop_reason: u32,
    _time: u64,
) -> i32 {
    if find_session_for_pid(pid).is_some() {
        0
    } else {
        DBGP_ERROR_INVALID_ARGUMENT
    }
}

unsafe extern "C" fn handle_is_process_attached(pid: SceUID) -> i32 {
    i32::from(find_session_for_pid(pid).is_some())
}

unsafe extern "C" fn handle_enable_watchpoint(_ops: *const SysrootDbgpHandler) -> i32 {
    0
}

unsafe extern "C" fn handle_disable_watchpoint(_ops: *const SysrootDbgpHandler) -> i32 {
    0
}

unsafe extern "C" fn handle_update_ulobjmgr_for_dbgp(
    _dbgp: *mut c_void,
    _process: *mut c_void,
    set: u32,
    _clear: u32,
    flag: *mut u32,
) -> i32 {
    if !flag.is_null() {
        unsafe { *flag = set };
    }
    0
}

unsafe extern "C" fn handle_update_ulobjmgr_for_fiber(_pid: SceUID, flag: *mut u32) -> i32 {
    if flag.is_null() {
        return DBGP_ERROR_INVALID_ARGUMENT;
    }
    unsafe { *flag = 0 };
    0
}

static DBGP_HANDLER: SysrootDbgpHandler = SysrootDbgpHandler {
    size: size_of::<SysrootDbgpHandler>() as u32,
    processStart: Some(handle_process_start),
    processExit: Some(handle_process_exit),
    processKill: Some(handle_process_kill),
    processSpontaneousExit: Some(handle_process_spontaneous_exit),
    processExitToSpawn: Some(handle_process_exit_to_spawn),
    exitSpawn: Some(handle_exit_spawn),
    processSuspend: Some(handle_process_suspend),
    processResume: Some(handle_process_resume),
    appAbort: Some(handle_app_abort),
    moduleStart: Some(handle_module_start),
    moduleStop: Some(handle_module_stop),
    isDebugTarget: Some(handle_is_debug_target),
    isPsButtonCaptured: Some(handle_is_ps_button_captured),
    swBkptGetOriginalOpcode: Some(handle_get_original_opcode),
    codeModified: Some(handle_code_modified),
    getPrxDebugFlag: Some(handle_get_prx_debug_flag),
    suspendProcessAndWaitResume: Some(handle_suspend_process_and_wait_resume),
    isProcessAttached: Some(handle_is_process_attached),
    enableWatchpoint: Some(handle_enable_watchpoint),
    disableWatchpoint: Some(handle_disable_watchpoint),
    updateUlobjmgrFlagForDbgp: Some(handle_update_ulobjmgr_for_dbgp),
    updateUlobjmgrFlagForLibfiber: Some(handle_update_ulobjmgr_for_fiber),
};

pub fn register_process_handlers() -> Result<(), SceError> {
    sce_call!(ksceKernelSysrootRegisterDbgpHandler(&DBGP_HANDLER))?;
    Ok(())
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

pub fn register_sysevent_handler() -> Result<(), SceError> {
    sce_call!(ksceKernelRegisterSysEventHandler(
        c"enable_debug".as_ptr(),
        Some(handle_sysevent),
        null_mut()
    ))?;
    Ok(())
}
