use core::{ffi::c_void, ptr::null_mut};

use vitasdk_sys::{
    SceObjectBase, ksceGUIDReferObject, ksceGUIDReleaseObject, ksceKernelCheckDipsw,
    ksceKernelSetDipsw,
};

use crate::{
    kernel::{ffi::spl_is_loaded, utils::SceError},
    mep::mep_write32,
    println,
};

pub fn enable_debug() -> Result<(), SceError> {
    if !spl_is_loaded() {
        println!("no psp2spl, not enabling hw breakpoints.");
        return Ok(());
    }
    if true {
        // broken so dont do it
        return Ok(());
    }
    mep_write32(0xE3101004, 0)?; // ScePervasiveReset cp14
    mep_write32(0xE3102004, 1)?; // ScePervasiveGate cp14
    hacky_fix_kernel();
    unsafe {
        ksceKernelSetDipsw(0xe4);
    } // cp14 enabled
    Ok(())
}

pub fn is_debug_enabled() -> bool {
    unsafe { ksceKernelCheckDipsw(0xe4) == 1 }
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
