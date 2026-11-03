use core::ffi::{CStr, c_void};
use core::ptr::null_mut;

use vitasdk_sys::{
    SCE_KERNEL_BACKTRACE_MODE_USER, SceExcpmgrExceptionContext, SceKernelCallFrame,
    SceKernelThreadInfo, SceUID, ksceGUIDName, ksceKernelBacktrace,
    ksceKernelFindProcMemBlockByAddr, ksceKernelGetMemBlockBase, kscePUIDtoGUID,
};

use crate::gdb::sessions::ExceptionKind;
use crate::kernel::ffi::ksceKernelGetModuleIdByAddrForDebugger;
use crate::kernel::utils::{get_module_info, get_thread_info, name_to_str};
use crate::{print, println, sce_call};

struct StackInfo {
    start: u64,
    end: u64,
    sp: u32,
}

pub fn report_exception(
    context: &SceExcpmgrExceptionContext,
    pid: SceUID,
    tid: SceUID,
    kind: ExceptionKind,
    fault_addr: u32,
) {
    let title = match kind {
        ExceptionKind::Dabt => "data abort",
        ExceptionKind::Pabt => "prefetch abort",
        ExceptionKind::Undef => "undefined instruction",
    };
    let fault_addr = matches!(kind, ExceptionKind::Dabt).then_some(fault_addr);
    report(title, context, pid, tid, fault_addr);
}

pub fn report_break(context: &SceExcpmgrExceptionContext, pid: SceUID, tid: SceUID) {
    report("breakpoint", context, pid, tid, None);
}

pub fn report_watch(context: &SceExcpmgrExceptionContext, pid: SceUID, tid: SceUID, write: bool) {
    let title = if write {
        "watchpoint (write)"
    } else {
        "watchpoint (read)"
    };
    report(title, context, pid, tid, Some(context.DFAR));
}

fn report(
    title: &str,
    context: &SceExcpmgrExceptionContext,
    pid: SceUID,
    tid: SceUID,
    fault_addr: Option<u32>,
) {
    println!("\n{title} pid={pid} tid={tid}");

    let thread = get_thread_info(tid).ok();
    let stack = thread
        .as_ref()
        .and_then(|info| stack_info(info, context.sp));
    if let Some(info) = &thread {
        let name = name_to_str(info.name.as_slice());
        match &stack {
            Some(stack) => println!(
                "  thread={name} stack=0x{:08x}..0x{:08x}",
                stack.start, stack.end
            ),
            None => println!("  thread={name}"),
        }
    }

    print_word(
        "pc",
        context.address_of_faulting_instruction,
        pid,
        stack.as_ref(),
    );
    print_word("lr", context.lr, pid, stack.as_ref());
    print_word("sp", context.sp, pid, stack.as_ref());

    println!(
        "  spsr  0x{:08x}  mode={} thumb={}",
        context.SPSR,
        mode_name(context.SPSR),
        if context.SPSR & (1 << 5) != 0 {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "  ifsr  0x{:08x}  ifar=0x{:08x}  dfsr=0x{:08x}{}  dfar=0x{:08x}",
        context.IFSR,
        context.IFAR,
        context.DFSR,
        if dfsr_is_write(context.DFSR) {
            " (write)"
        } else {
            " (read)"
        },
        context.DFAR
    );

    if let Some(addr) = fault_addr {
        print_word("fault", addr, pid, stack.as_ref());
    }

    for (name, value) in [
        ("r0", context.r0),
        ("r1", context.r1),
        ("r2", context.r2),
        ("r3", context.r3),
        ("r4", context.r4),
        ("r5", context.r5),
        ("r6", context.r6),
        ("r7", context.r7),
        ("r8", context.r8),
        ("r9", context.r9),
        ("r10", context.r10),
        ("r11", context.r11),
        ("r12", context.r12),
    ] {
        print_word(name, value, pid, stack.as_ref());
    }

    print_backtrace(pid, tid, stack.as_ref());

    print!("\n");
}

fn print_backtrace(pid: SceUID, tid: SceUID, stack: Option<&StackInfo>) {
    let mut frames = [SceKernelCallFrame { sp: 0, pc: 0 }; 32];
    let mut num_frames = 0;
    if let Err(err) = sce_call!(ksceKernelBacktrace(
        tid,
        frames.as_mut_ptr(),
        (frames.len() as u32) * (core::mem::size_of::<SceKernelCallFrame>() as u32),
        &mut num_frames,
        SCE_KERNEL_BACKTRACE_MODE_USER as _,
    )) {
        println!("  backtrace: {err}");
        return;
    }

    let count = (num_frames as usize).min(frames.len());
    if count == 0 {
        println!("  backtrace: empty");
        return;
    }

    println!("  backtrace:");
    for (index, frame) in frames.iter().take(count).enumerate() {
        println!("  #{index:<2} sp=0x{:08x}", frame.sp as u32);
        print_word("pc", frame.pc as u32, pid, stack);
    }
}

fn stack_info(info: &SceKernelThreadInfo, sp: u32) -> Option<StackInfo> {
    let start = info.stack as usize as u64;
    let size = info.stackSize.max(0) as u64;
    if size == 0 {
        return None;
    }
    Some(StackInfo {
        start,
        end: start.saturating_add(size),
        sp,
    })
}

fn print_word(label: &str, value: u32, pid: SceUID, stack: Option<&StackInfo>) {
    print!("  {label:<5} 0x{value:08x}");

    if let Some(stack) = stack {
        let addr = value as u64;
        if addr >= stack.start && addr < stack.end {
            let offset = addr - stack.start;
            let sp_offset = addr as i64 - stack.sp as i64;
            print!("  stack+0x{offset:x} (");
            if sp_offset >= 0 {
                print!("sp+0x{:x}", sp_offset as u64);
            } else {
                print!("sp-0x{:x}", (-sp_offset) as u64);
            }
            println!(")");
            return;
        }
    }

    if print_module(pid, value) {
        return;
    }

    if print_block(pid, value) {
        return;
    }

    println!("  {value}");
}

fn print_module(pid: SceUID, addr: u32) -> bool {
    let Ok(mod_puid) = sce_call!(ksceKernelGetModuleIdByAddrForDebugger(
        pid,
        addr as *const c_void
    )) else {
        return false;
    };
    let Ok(modid) = sce_call!(kscePUIDtoGUID(pid, mod_puid)) else {
        println!("  module:0x{mod_puid:x}");
        return true;
    };
    let Ok(info) = get_module_info(pid, modid) else {
        println!("  module:0x{modid:x}");
        return true;
    };
    let name = name_to_str(info.module_name.as_slice());
    let addr = addr as u64;
    let offset = info
        .segments
        .iter()
        .filter(|segment| segment.memsz != 0)
        .find_map(|segment| {
            let start = segment.vaddr as usize as u64;
            let end = start.saturating_add(segment.memsz as u64);
            (addr >= start && addr < end).then_some((addr - start) as u32)
        })
        .unwrap_or_default();
    println!("  module:{name:<20}+0x{offset:x}");
    true
}

fn print_block(pid: SceUID, addr: u32) -> bool {
    let Ok(uid) = sce_call!(ksceKernelFindProcMemBlockByAddr(
        pid,
        addr as *const c_void,
        0
    )) else {
        return false;
    };

    let name_ptr = unsafe { ksceGUIDName(uid) };
    let name = if name_ptr.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(name_ptr) }.to_str().ok()
    };

    let mut base: *mut c_void = null_mut();
    let offset = if sce_call!(ksceKernelGetMemBlockBase(uid, &mut base)).is_ok() {
        (addr as usize as u64).checked_sub(base as usize as u64)
    } else {
        None
    };

    match (name, offset) {
        (Some(name), Some(offset)) => println!("  block:{name:<20}+0x{offset:x}"),
        (Some(name), None) => println!("  block:{name:<20}"),
        (None, Some(offset)) => println!("  block:0x{uid:x}+0x{offset:x}"),
        (None, None) => println!("  block:0x{uid:x}"),
    }
    true
}

fn dfsr_is_write(dfsr: u32) -> bool {
    dfsr & (1 << 11) != 0
}

fn mode_name(spsr: u32) -> &'static str {
    match spsr & 0x1f {
        0x10 => "user",
        0x11 => "fiq",
        0x12 => "irq",
        0x13 => "svc",
        0x17 => "abort",
        0x1b => "undef",
        0x1f => "system",
        _ => "unknown",
    }
}
