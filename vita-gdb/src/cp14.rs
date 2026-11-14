use vitasdk_sys::ksceKernelCheckDipsw;

use crate::{
    kernel::{ffi::spl_is_loaded, utils::SceError},
    mep::spl_exec,
    println, sce_call,
};

use core::{ffi::c_void, ptr::null_mut};

use vitasdk_sys::{
    SceObjectBase, ksceGUIDReferObject, ksceGUIDReleaseObject, ksceKernelRegisterSysEventHandler, ksceKernelSetDipsw,
};

const CP14_NMP: [u8; 60] = [
    0x21, 0xc3, 0x10, 0xe3, 0x34, 0xc3, 0x00, 0x20, 0x21, 0xc1, 0xf0, 0x00, 0x3e, 0x02, 0x00, 0x50, 0x10, 0x12, 0x3a,
    0x02, 0x21, 0xc3, 0x10, 0xe3, 0x34, 0xc3, 0x04, 0x20, 0xfe, 0x51, 0x3e, 0x02, 0x24, 0xc2, 0x01, 0x00, 0x3a, 0x02,
    0x21, 0xc3, 0x10, 0xe3, 0x34, 0xc3, 0x04, 0x10, 0x3e, 0x02, 0x11, 0x12, 0x3a, 0x02, 0x02, 0x70, 0x00, 0x00, 0xf0,
    0xff, 0x1f, 0x00,
];

const SCE_DIPSW_HW_DEBUG: u32 = 0xe4;

pub fn enable_debug() -> Result<(), SceError> {
    let val = unsafe { ksceKernelCheckDipsw(SCE_DIPSW_HW_DEBUG) };
    if val == 1 {
        return Ok(());
    }

    if !spl_is_loaded() {
        println!("no psp2spl, not enabling hw breakpoints.");
        return Ok(());
    }
    spl_exec(&CP14_NMP, 0)?;
    hacky_fix_kernel();
    unsafe {
        ksceKernelSetDipsw(SCE_DIPSW_HW_DEBUG);
    } // cp14 enabled
    Ok(())
}

fn hacky_fix_kernel() {
    // fix SceUIDProcessObject(0x10005)->bpkt_ctx_field58 being null
    static FIXUP_VAL: [u32; 2] = [0; 2];
    let mut kernel: *mut SceObjectBase = null_mut();
    unsafe { ksceGUIDReferObject(0x10005, &mut kernel) };
    let kernel = kernel as *mut c_void;
    let bkpt_ctx_field58 = unsafe { kernel.byte_add(0x288) as *mut u32 };
    unsafe { bkpt_ctx_field58.write(FIXUP_VAL.as_ptr() as _) }
    unsafe { ksceGUIDReleaseObject(0x10005) };
}

pub fn is_debug_enabled() -> bool { unsafe { ksceKernelCheckDipsw(0xe4) == 1 } }

unsafe extern "C" fn handle_sysevent(resume: i32, eventid: i32, _args: *mut c_void, _opt: *mut c_void) -> i32 {
    if resume != 0 && eventid == 0x100000 {
        //if let Err(err) = enable_debug() {
        //    println!("enable_debug: {err}");
        //}
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
