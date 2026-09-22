use vitasdk_sys::SceUID;

use crate::kernel::{
    ffi::{spl_exec_code, spl_is_loaded},
    utils::{SceError, map_paddr},
};

// https://github.com/SKGleba/psp2spl/tree/master/samples/pspemu_brom_exec
const BRIDGE_NMP: [u8; 68] = [
    0x80, 0x6f, 0x1a, 0x7b, 0x16, 0x4b, 0x1e, 0xc9, 0x20, 0x00, 0x1e, 0xc4, 0x10, 0x00, 0x1e, 0xc3,
    0x0c, 0x00, 0x1e, 0xc2, 0x08, 0x00, 0x1e, 0xc0, 0x04, 0x00, 0x0e, 0x49, 0x1e, 0xc9, 0x1c, 0x00,
    0x0a, 0x49, 0x1e, 0xc9, 0x18, 0x00, 0x06, 0x49, 0x1e, 0xc9, 0x14, 0x00, 0xfa, 0x09, 0x1e, 0x09,
    0x00, 0x01, 0x9f, 0x10, 0x17, 0x4b, 0x20, 0x4f, 0xbe, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf0, 0xff, 0x1f, 0x00,
];

const FUD_COMMS_PA: u32 = 0x1F85C000;
const FUD_COMMS_SIZE: usize = 0x4000;

static mut FUD_COMMS: Option<(SceUID, *mut u8)> = None;

fn fud_init() -> Result<(), SceError> {
    let (uid, base) = map_paddr(c"fud_comms", FUD_COMMS_PA, FUD_COMMS_SIZE)?;
    unsafe { FUD_COMMS = Some((uid, base as *mut u8)) };
    Ok(())
}

#[repr(C)]
struct FudBridgeData {
    paddr: u32,
    args: [u32; 8],
}

fn fud_bridge_exec(exec_addr: u32, args: &[u32]) -> Result<u32, SceError> {
    if !spl_is_loaded() {
        return Err(SceError::new(-1, "fud_bridge_exec: psp2spl not loaded"));
    }
    if unsafe { FUD_COMMS }.is_none() {
        fud_init()?;
    }
    let bridge_data = match unsafe { FUD_COMMS } {
        Some(comms) => unsafe { &mut *(comms.1 as *mut FudBridgeData) },
        None => return Err(SceError::new(-3, "fud_bridge_exec")),
    };
    bridge_data.paddr = exec_addr;
    for (i, arg) in args.iter().take(8).enumerate() {
        bridge_data.args[i] = *arg;
    }
    match unsafe {
        spl_exec_code(
            BRIDGE_NMP.as_ptr() as _,
            BRIDGE_NMP.len(),
            FUD_COMMS_PA,
            true,
        )
    } {
        1 => Err(SceError::new(-1, "fud_bridge_exec")),
        2 => Err(SceError::new(-2, "fud_bridge_exec")),
        3 => Err(SceError::new(-3, "fud_bridge_exec")),
        val => Ok(val),
    }
}

pub fn mep_write32(dst: u32, val: u32) -> Result<(), SceError> {
    fud_bridge_exec(0x00807262, &[dst, FUD_COMMS_PA + 0x10, 0x4, val])?;
    Ok(())
}

pub fn mep_read32(addr: u32) -> Result<u32, SceError> {
    fud_bridge_exec(0x00807262, &[FUD_COMMS_PA + 0x10, addr, 0x4])?;
    let value = unsafe { FUD_COMMS.unwrap().1.add(0x10).cast::<u32>().read_volatile() };
    Ok(value)
}
