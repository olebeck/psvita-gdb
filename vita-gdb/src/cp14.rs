use core::{ffi::c_void, ptr::null_mut};

use vitasdk_sys::{
    SceObjectBase, ksceGUIDReferObject, ksceGUIDReleaseObject, ksceKernelCheckDipsw,
    ksceKernelSetDipsw,
};

use crate::{
    kernel::{ffi::spl_is_loaded, syscon::scratch_switch, utils::SceError},
    mep::spl_exec,
    println,
};

const CP14_NMP: [u8; 60] = [
    0x21, 0xc3, 0x10, 0xe3, 0x34, 0xc3, 0x00, 0x20, 0x21, 0xc1, 0xf0, 0x00, 0x3e, 0x02, 0x00, 0x50,
    0x10, 0x12, 0x3a, 0x02, 0x21, 0xc3, 0x10, 0xe3, 0x34, 0xc3, 0x04, 0x20, 0x3e, 0x02, 0x24, 0xc2,
    0x01, 0x00, 0x3a, 0x02, 0x21, 0xc3, 0x10, 0xe3, 0x34, 0xc3, 0x04, 0x10, 0x3e, 0x02, 0x24, 0xc2,
    0x01, 0x00, 0x3a, 0x02, 0x02, 0x70, 0x00, 0x00, 0xf0, 0xff, 0x1f, 0x00,
];

pub fn enable_debug() -> Result<(), SceError> {
    scratch_switch(0xe4, true)?;

    let val = unsafe { ksceKernelCheckDipsw(0xe4) };
    println!("ksceKernelCheckDipsw(0xe4): {}", val);
    return Ok(());

    if !spl_is_loaded() {
        println!("no psp2spl, not enabling hw breakpoints.");
        return Ok(());
    }
    spl_exec(&CP14_NMP, 0)?;
    hacky_fix_kernel();
    if false {
        unsafe {
            ksceKernelSetDipsw(0xe4);
        } // cp14 enabled
    }
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
