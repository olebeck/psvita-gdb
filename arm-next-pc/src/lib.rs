#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(any(feature = "exarmo")))]
compile_error!("exarmo must be enabled");

#[cfg(feature = "exarmo")]
mod next_pc_exarmo;

#[cfg(feature = "exarmo")]
pub use next_pc_exarmo::next_pc;

#[cfg(feature = "std")]
mod tests;
#[cfg(all(feature = "std", test))]
mod tests2;

pub trait MemReader {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Option<()>;

    fn read_u8(&self, addr: u32) -> Result<u8, NextPcError> {
        let mut bytes = [0; 1];
        self.read(addr as usize, &mut bytes).ok_or(NextPcError::MemoryRead)?;
        Ok(bytes[0])
    }

    fn read_u16(&self, addr: u32) -> Result<u16, NextPcError> {
        let mut bytes = [0; 2];
        self.read(addr as usize, &mut bytes).ok_or(NextPcError::MemoryRead)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&self, addr: u32) -> Result<u32, NextPcError> {
        let mut bytes = [0; 4];
        self.read(addr as usize, &mut bytes).ok_or(NextPcError::MemoryRead)?;
        Ok(u32::from_le_bytes(bytes))
    }
}

#[derive(Default)]
pub struct RegContext {
    pub r: [u32; 13],
    pub sp: u32,
    pub lr: u32,
    pub pc: u32,
    pub cpsr: u32,
    pub spsr: u32,
}

impl RegContext {
    fn thumb(&self) -> bool { (self.cpsr >> 5) & 1 != 0 }

    fn reg(&self, idx: u8) -> u32 {
        match idx {
            0..13 => self.r.get(idx as usize).copied().unwrap_or(0xdeadbeef),
            13 => self.sp,
            14 => self.lr,
            15 => self.pc,
            _ => 0xdeadbeef,
        }
    }

    fn cond_flags(&self) -> (bool, bool, bool, bool) {
        // N, Z, C, V
        (
            (self.cpsr & (1 << 31)) != 0,
            (self.cpsr & (1 << 30)) != 0,
            (self.cpsr & (1 << 29)) != 0,
            (self.cpsr & (1 << 28)) != 0,
        )
    }
}

#[derive(Debug)]
pub enum NextPcError {
    MemoryRead,
    DecodeError,
}
