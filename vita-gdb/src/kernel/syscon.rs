use core::mem;

use vitasdk_sys::{
    SCE_SYSCON_PACKET_TX_CMD_HI, SCE_SYSCON_PACKET_TX_CMD_LO, SCE_SYSCON_PACKET_TX_LENGTH,
    SceSysconPacket, ksceSysconCmdExec,
};

use crate::{kernel::utils::SceError, sce_call};

const SCRATCH_SIZE: usize = 0x100;
const SCRATCH_CHUNK: usize = 0x100;
const DIPSW_SCRATCH_OFFSET: u32 = 0xe0;

const SYSCON_CMD_READ_SCRATCH: u32 = 0x90;
const SYSCON_CMD_WRITE_SCRATCH: u32 = 0x91;

const SCE_SYSCON_PACKET_TX_DATA: usize = 3;
const SCE_SYSCON_PACKET_RX_DATA: usize = 4;

pub const SYSCON_COLD_RESET: u32 = 0x0801;

fn scratch_packet_new(command: u32, offset: u32, size: usize) -> SceSysconPacket {
    let mut packet: SceSysconPacket = unsafe { mem::zeroed() };
    let mut set = |index: usize, val: u8| {
        if let Some(slot) = packet.tx.get_mut(index) {
            *slot = val;
        }
    };
    set(SCE_SYSCON_PACKET_TX_CMD_LO as usize, (command & 0xff) as u8);
    set(SCE_SYSCON_PACKET_TX_CMD_HI as usize, (command >> 8) as u8);
    set(SCE_SYSCON_PACKET_TX_DATA, (offset & 0xff) as u8);
    set(SCE_SYSCON_PACKET_TX_DATA + 1, (offset >> 8) as u8);
    set(SCE_SYSCON_PACKET_TX_DATA + 2, size as u8);
    set(SCE_SYSCON_PACKET_TX_LENGTH as usize, 4);
    packet
}

fn syscon_scratch_read_packet(offset: u32, data: &mut [u8]) -> Result<(), SceError> {
    let mut packet = scratch_packet_new(SYSCON_CMD_READ_SCRATCH, offset, data.len());
    sce_call!(ksceSysconCmdExec(&mut packet, 0))?;
    if let Some(src_slice) = packet.rx.get(SCE_SYSCON_PACKET_RX_DATA..) {
        for (dest, src) in data.iter_mut().zip(src_slice.iter()) {
            *dest = *src;
        }
    }
    Ok(())
}

fn syscon_scratch_write_packet(offset: u32, data: &[u8]) -> Result<(), SceError> {
    let mut packet = scratch_packet_new(SYSCON_CMD_WRITE_SCRATCH, offset, data.len());
    if let Some(dest_slice) = packet.tx.get_mut(SCE_SYSCON_PACKET_TX_DATA + 3..) {
        for (dest, &src) in dest_slice.iter_mut().zip(data.iter()) {
            *dest = src;
        }
    }
    let total_len = 4_usize.saturating_add(data.len());
    let len_u8 = total_len.min(u8::MAX as usize) as u8;
    if let Some(len_field) = packet.tx.get_mut(SCE_SYSCON_PACKET_TX_LENGTH as usize) {
        *len_field = len_u8;
    }
    sce_call!(ksceSysconCmdExec(&mut packet, 0))?;
    Ok(())
}

fn scratch_check_range(offset: u32, size: usize) -> Result<(), SceError> {
    static UNAVAILABLE: SceError = SceError::new(-1, "scratch_check_range");
    let end = (offset as usize).checked_add(size).ok_or(UNAVAILABLE)?;
    if end > SCRATCH_SIZE {
        return Err(UNAVAILABLE);
    }
    Ok(())
}

pub fn syscon_scratch_read(offset: u32, data: &mut [u8]) -> Result<(), SceError> {
    scratch_check_range(offset, data.len())?;

    let mut done = 0u32;
    for chunk in data.chunks_mut(SCRATCH_CHUNK) {
        syscon_scratch_read_packet(offset.saturating_add(done), chunk)?;
        done = done.saturating_add(chunk.len() as _);
    }
    Ok(())
}

pub fn syscon_scratch_write(offset: u32, data: &[u8]) -> Result<(), SceError> {
    scratch_check_range(offset, data.len())?;

    let mut done = 0u32;
    for chunk in data.chunks(SCRATCH_CHUNK) {
        syscon_scratch_write_packet(offset.saturating_add(done), chunk)?;
        done = done.saturating_add(chunk.len() as _);
    }
    Ok(())
}

pub fn scratch_switch(sw: u32, on: bool) -> Result<(), SceError> {
    static UNAVAILABLE: SceError = SceError::new(-1, "scratch_switch");

    if sw > 0xff || sw == 0x80 || sw == 0xd2 {
        return Err(UNAVAILABLE);
    }

    let offset = DIPSW_SCRATCH_OFFSET.wrapping_add(sw >> 3);
    let mask = 1u8 << (sw & 7);
    let mut byte = [0u8; 1];

    syscon_scratch_read(offset, &mut byte)?;
    byte[0] = if on { byte[0] | mask } else { byte[0] & !mask };
    syscon_scratch_write(offset, &byte)?;
    Ok(())
}

pub fn syscon_cmd(command: u32) -> Result<(), SceError> {
    let mut packet: SceSysconPacket = unsafe { mem::zeroed() };
    let mut set = |index: usize, val: u8| {
        if let Some(slot) = packet.tx.get_mut(index) {
            *slot = val;
        }
    };
    set(SCE_SYSCON_PACKET_TX_CMD_LO as usize, (command & 0xff) as u8);
    set(SCE_SYSCON_PACKET_TX_CMD_HI as usize, (command >> 8) as u8);
    set(SCE_SYSCON_PACKET_TX_LENGTH as usize, 1);
    sce_call!(ksceSysconCmdExec(&mut packet, 0))?;
    Ok(())
}
