use core::num::NonZeroUsize;

use gdbstub::arch::{Arch, RegId, Registers};
use gdbstub_arch::arm::ArmBreakpointKind;

pub enum Armv7 {}

impl Arch for Armv7 {
    type Usize = u32;
    type Registers = Armv7Regs;
    type RegId = Armv7RegId;
    type BreakpointKind = ArmBreakpointKind;

    fn target_description_xml() -> Option<&'static str> {
        Some(
            r#"
<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
    <architecture>armv7</architecture>
    <feature name="org.gnu.gdb.arm.core">
        <reg name="r0"  bitsize="32" type="uint32"/>
        <reg name="r1"  bitsize="32" type="uint32"/>
        <reg name="r2"  bitsize="32" type="uint32"/>
        <reg name="r3"  bitsize="32" type="uint32"/>
        <reg name="r4"  bitsize="32" type="uint32"/>
        <reg name="r5"  bitsize="32" type="uint32"/>
        <reg name="r6"  bitsize="32" type="uint32"/>
        <reg name="r7"  bitsize="32" type="uint32"/>
        <reg name="r8"  bitsize="32" type="uint32"/>
        <reg name="r9"  bitsize="32" type="uint32"/>
        <reg name="r10" bitsize="32" type="uint32"/>
        <reg name="r11" bitsize="32" type="uint32"/>
        <reg name="r12" bitsize="32" type="uint32"/>
        <reg name="sp"  bitsize="32" type="data_ptr"/>
        <reg name="lr"  bitsize="32" type="uint32"/>
        <reg name="pc"  bitsize="32" type="code_ptr"/>
        <reg name="cpsr" bitsize="32" type="uint32"/>
    </feature>
    <feature name="org.gnu.gdb.arm.vfp">
        <reg name="d0"  bitsize="64" type="ieee_double"/>
        <reg name="d1"  bitsize="64" type="ieee_double"/>
        <reg name="d2"  bitsize="64" type="ieee_double"/>
        <reg name="d3"  bitsize="64" type="ieee_double"/>
        <reg name="d4"  bitsize="64" type="ieee_double"/>
        <reg name="d5"  bitsize="64" type="ieee_double"/>
        <reg name="d6"  bitsize="64" type="ieee_double"/>
        <reg name="d7"  bitsize="64" type="ieee_double"/>
        <reg name="d8"  bitsize="64" type="ieee_double"/>
        <reg name="d9"  bitsize="64" type="ieee_double"/>
        <reg name="d10" bitsize="64" type="ieee_double"/>
        <reg name="d11" bitsize="64" type="ieee_double"/>
        <reg name="d12" bitsize="64" type="ieee_double"/>
        <reg name="d13" bitsize="64" type="ieee_double"/>
        <reg name="d14" bitsize="64" type="ieee_double"/>
        <reg name="d15" bitsize="64" type="ieee_double"/>
        <reg name="d16" bitsize="64" type="ieee_double"/>
        <reg name="d17" bitsize="64" type="ieee_double"/>
        <reg name="d18" bitsize="64" type="ieee_double"/>
        <reg name="d19" bitsize="64" type="ieee_double"/>
        <reg name="d20" bitsize="64" type="ieee_double"/>
        <reg name="d21" bitsize="64" type="ieee_double"/>
        <reg name="d22" bitsize="64" type="ieee_double"/>
        <reg name="d23" bitsize="64" type="ieee_double"/>
        <reg name="d24" bitsize="64" type="ieee_double"/>
        <reg name="d25" bitsize="64" type="ieee_double"/>
        <reg name="d26" bitsize="64" type="ieee_double"/>
        <reg name="d27" bitsize="64" type="ieee_double"/>
        <reg name="d28" bitsize="64" type="ieee_double"/>
        <reg name="d29" bitsize="64" type="ieee_double"/>
        <reg name="d30" bitsize="64" type="ieee_double"/>
        <reg name="d31" bitsize="64" type="ieee_double"/>
        <reg name="fpscr" bitsize="32" type="uint32"/>
    </feature>
    <feature name="org.gnu.gdb.arm.neon"/>
</target>
"#,
        )
    }
}

/// 32-bit ARM core register identifier.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Armv7RegId {
    /// General purpose registers (R0-R12)
    Gpr(u8),
    /// Stack Pointer (R13)
    Sp,
    /// Link Register (R14)
    Lr,
    /// Program Counter (R15)
    Pc,
    /// Current Program Status Register (cpsr)
    Cpsr,
    /// VFP/NEON D registers (D0-D31).
    Dpr(u8),
    //// Floating Point Status and Control Register.
    Fpscr,
}

impl RegId for Armv7RegId {
    fn from_raw_id(id: usize) -> Option<(Self, Option<NonZeroUsize>)> {
        let reg = match id {
            0..=12 => Self::Gpr(id as u8),
            13 => Self::Sp,
            14 => Self::Lr,
            15 => Self::Pc,
            16 => Self::Cpsr,
            17..=48 => Self::Dpr((id - 17) as u8),
            49 => Self::Fpscr,
            _ => return None,
        };
        let size = match reg {
            Self::Dpr(_) => 8,
            _ => 4,
        };
        Some((reg, NonZeroUsize::new(size)))
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct Armv7Regs {
    /// General purpose registers (R0-R12)
    pub r: [u32; 13],
    /// Stack Pointer (R13)
    pub sp: u32,
    /// Link Register (R14)
    pub lr: u32,
    /// Program Counter (R15)
    pub pc: u32,
    /// Current Program Status Register (cpsr)
    pub cpsr: u32,
    // VFPv3 / NEON D0-D31
    pub d: [u64; 32],
    /// Floating Point Status and Control Register.
    pub fpscr: u32,
}

impl Registers for Armv7Regs {
    type ProgramCounter = u32;

    fn pc(&self) -> Self::ProgramCounter {
        self.pc
    }

    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        macro_rules! write_le {
            ($value:expr) => {
                for byte in $value.to_le_bytes() {
                    write_byte(Some(byte));
                }
            };
        }
        // org.gnu.gdb.arm.core
        for reg in &self.r {
            write_le!(*reg);
        }

        write_le!(self.sp);
        write_le!(self.lr);
        write_le!(self.pc);
        write_le!(self.cpsr);

        // org.gnu.gdb.arm.vfp
        for reg in &self.d {
            write_le!(*reg);
        }
        write_le!(self.fpscr);
    }

    fn gdb_deserialize(&mut self, mut bytes: &[u8]) -> Result<(), ()> {
        const EXPECTED_LEN: usize = 17 * 4 + 32 * 8 + 1 * 4;

        if bytes.len() != EXPECTED_LEN {
            return Err(());
        }

        // org.gnu.gdb.arm.core
        for reg in &mut self.r {
            *reg = next_u32(&mut bytes)?;
        }

        self.sp = next_u32(&mut bytes)?;
        self.lr = next_u32(&mut bytes)?;
        self.pc = next_u32(&mut bytes)?;
        self.cpsr = next_u32(&mut bytes)?;

        // org.gnu.gdb.arm.vfp
        for reg in &mut self.d {
            *reg = next_u64(&mut bytes)?;
        }
        self.fpscr = next_u32(&mut bytes)?;

        if !bytes.is_empty() {
            return Err(());
        }

        Ok(())
    }
}

fn next_u32(bytes: &mut &[u8]) -> Result<u32, ()> {
    if bytes.len() < 4 {
        return Err(());
    }
    let (next, rest) = bytes.split_at(4);
    *bytes = rest;
    Ok(u32::from_le_bytes(next.try_into().map_err(|_| ())?))
}

fn next_u64(bytes: &mut &[u8]) -> Result<u64, ()> {
    if bytes.len() < 8 {
        return Err(());
    }
    let (next, rest) = bytes.split_at(8);
    *bytes = rest;
    Ok(u64::from_le_bytes(next.try_into().map_err(|_| ())?))
}
