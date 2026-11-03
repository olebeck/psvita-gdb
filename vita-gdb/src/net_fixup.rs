use core::mem::zeroed;

use vitasdk_sys::{SceKernelModuleInfo, ksceKernelSearchModuleByName};

use crate::{
    kernel::{
        ffi::{ksceKernelGetModuleInfo, taiInjectDataForKernel},
        utils::SceError,
    },
    println, sce_call,
};

const ORIG_CODE: [u8; 26] = [
    0xC0, 0xEF, 0x10, 0x00, // vmov.i32	d16, #0
    0x19, 0x68, // ldr		r1, [r3]
    0xA2, 0x60, // str		r2, [r4, #8]
    0xDA, 0xF8, 0x0C, 0x30, // ldr.w	r3, [r10, #0xC]
    0xC4, 0xE9, 0x07, 0x55, // strd r5, r5, [r4, #0x1C]
    0xA5, 0x61, // str		r5, [r4, #0x18]
    0xE3, 0x60, // str		r3, [r4, #0xC]
    0x61, 0x62, // str		r1, [r4, #0x24]
    0xC4, 0xED, 0x04, 0x0B, // vstr.64	d16, [r4, #0x10]
];

const PATCHED_CODE: [u8; 26] = [
    0xDD, 0xF8, 0x30, 0xC0, // ldr		r12, [sp, #0x30]	!!!
    0x19, 0x68, // ldr		r1, [r3]
    0xA2, 0x60, // str		r2, [r4, #8]
    0xDA, 0xF8, 0x0C, 0x30, // ldr.w	r3, [r10, #0xC]
    0xC4, 0xE9, 0x07, 0xC5, // strd		r12, r5, [r4,#0x1c]	!!!
    0xA5, 0x61, // str		r5, [r4, #0x18]
    0xE3, 0x60, // str		r3, [r4, #0xC]
    0x61, 0x62, // str		r1, [r4, #0x24]
    0xC4, 0xE9, 0x04, 0x55, // strd		r5, r5, [r4,#0x10]	!!!
];

pub fn fixup_netrecv_bug() -> Result<(), SceError> {
    let netps_id = sce_call!(ksceKernelSearchModuleByName(c"SceNetPs".as_ptr() as _))?;
    let mut info: SceKernelModuleInfo = SceKernelModuleInfo {
        size: size_of::<SceKernelModuleInfo>() as _,
        ..unsafe { zeroed() }
    };
    sce_call!(ksceKernelGetModuleInfo(0x10005, netps_id, &raw mut info))?;
    let text = unsafe {
        core::slice::from_raw_parts(
            info.segments[0].vaddr as *const u8,
            info.segments[0].memsz as usize,
        )
    };
    let Some(offset) = text
        .windows(ORIG_CODE.len())
        .position(|window| window == ORIG_CODE.as_slice())
    else {
        println!("fixup_netrecv_bug: orig code not found");
        return Ok(());
    };
    sce_call!(taiInjectDataForKernel(
        0x10005,
        netps_id,
        0,
        offset as u32,
        PATCHED_CODE.as_ptr() as _,
        PATCHED_CODE.len()
    ))?;
    Ok(())
}
