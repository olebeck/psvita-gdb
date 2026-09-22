#![cfg_attr(not(feature = "std"), no_std)]

use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv7::{ConditionCode, DecodeError, InstDecoder, Opcode, Operand, Reg};

#[cfg(feature = "std")]
mod tests;

pub trait MemReader {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Option<()>;

    fn read_u8(&self, addr: u32) -> Result<u8, NextPcError> {
        let mut bytes = [0; 1];
        self.read(addr as usize, &mut bytes)
            .ok_or(NextPcError::MemoryRead)?;
        Ok(bytes[0])
    }

    fn read_u16(&self, addr: u32) -> Result<u16, NextPcError> {
        let mut bytes = [0; 2];
        self.read(addr as usize, &mut bytes)
            .ok_or(NextPcError::MemoryRead)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&self, addr: u32) -> Result<u32, NextPcError> {
        let mut bytes = [0; 4];
        self.read(addr as usize, &mut bytes)
            .ok_or(NextPcError::MemoryRead)?;
        Ok(u32::from_le_bytes(bytes))
    }
}

pub struct RegContext {
    pub r: [u32; 13],
    pub sp: u32,
    pub lr: u32,
    pub pc: u32,
    pub cpsr: u32,
    //pub fpscr: u32,
}

impl Default for RegContext {
    fn default() -> Self {
        Self {
            r: [0u32; 13],
            sp: 0,
            lr: 0,
            pc: 0,
            cpsr: 0,
            //fpscr: 0,
        }
    }
}

impl RegContext {
    fn thumb(&self) -> bool {
        (self.cpsr >> 5) & 1 != 0
    }

    fn reg(&self, reg: Reg) -> u32 {
        let idx = reg.number();
        match idx {
            0..13 => self.r[idx as usize],
            13 => self.sp,
            14 => self.lr,
            15 => self.pc,
            _ => unreachable!(),
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
    DecodeError(DecodeError),
}

pub fn next_pc<Mem: MemReader>(regs: &RegContext, mem: &Mem) -> Result<(u32, bool), NextPcError> {
    let addr = if regs.thumb() {
        regs.pc.wrapping_sub(4)
    } else {
        regs.pc.wrapping_sub(8)
    };
    let mut bytes = [0u8; 4];
    mem.read(addr as usize, &mut bytes)
        .ok_or(NextPcError::MemoryRead)?;

    let decoder = if regs.thumb() {
        InstDecoder::default_thumb()
    } else {
        InstDecoder::default()
    };
    let mut reader = U8Reader::new(&bytes);
    let insn = decoder
        .decode(&mut reader)
        .map_err(NextPcError::DecodeError)?;
    let fallthrough = (
        addr.wrapping_add(if insn.thumb && !insn.wide { 2 } else { 4 }),
        insn.thumb,
    );

    if !eval_cond(insn.condition, regs) {
        return Ok(fallthrough);
    }

    #[cfg(feature = "std")]
    println!("insn: {insn:?}");
    match insn.opcode {
        Opcode::B | Opcode::BL => match insn.operands[0] {
            Operand::BranchOffset(offset) => {
                Ok((regs.pc.wrapping_add(((offset - 2) << 2) as u32), false))
            }
            Operand::BranchThumbOffset(offset) => {
                Ok((thumb_branch_target(insn.condition, offset, regs), true))
            }
            _ => unreachable!(),
        },
        Opcode::BLX => match insn.operands[0] {
            Operand::BranchOffset(offset) => Ok((regs.pc.wrapping_add((offset << 2) as u32), true)),
            Operand::BranchThumbOffset(offset) => {
                Ok((regs.pc.wrapping_add((offset << 1) as u32), false))
            }
            Operand::Reg(reg) => {
                let value = regs.reg(reg);
                return Ok((value & !1, value & 1 == 1));
            }
            _ => unreachable!(),
        },
        Opcode::BX | Opcode::BXJ => match insn.operands[0] {
            Operand::Reg(reg) => {
                let value = regs.reg(reg);
                return Ok((value & !1, value & 1 == 1));
            }
            _ => unreachable!(),
        },
        Opcode::CBZ => match (insn.operands[0], insn.operands[1]) {
            (Operand::Reg(reg), Operand::Imm32(imm)) => {
                if regs.reg(reg) == 0 {
                    return Ok((imm & !1, imm & 1 == 1));
                }
                return Ok(fallthrough);
            }
            _ => unreachable!(),
        },
        Opcode::CBNZ => match (insn.operands[0], insn.operands[1]) {
            (Operand::Reg(reg), Operand::Imm32(imm)) => {
                if regs.reg(reg) != 0 {
                    return Ok((imm & !1, imm & 1 == 1));
                }
                return Ok(fallthrough);
            }
            _ => unreachable!(),
        },
        Opcode::AND
        | Opcode::EOR
        | Opcode::SUB
        | Opcode::RSB
        | Opcode::ADD
        | Opcode::ADC
        | Opcode::SBC
        | Opcode::RSC
        | Opcode::ORR
        | Opcode::MOV
        | Opcode::BIC
        | Opcode::MVN
        | Opcode::LSL
        | Opcode::LSR
        | Opcode::ASR
        | Opcode::RRX
        | Opcode::ROR
        | Opcode::ADR => {
            if is_pc_destination(insn.operands[0]) {
                let target = eval_alu(&insn.opcode, &insn.operands, regs);
                return Ok((target & !3, insn.thumb));
            }
            Ok(fallthrough)
        }
        Opcode::LDR | Opcode::LDRT => {
            if is_pc_destination(insn.operands[0]) {
                let address = effective_address(insn.operands[1], regs);
                let target = mem.read_u32(address)?;
                return Ok((target & !1, target & 1 == 1));
            }
            Ok(fallthrough)
        }
        Opcode::LDM(_, _, _, _) | Opcode::POP => {
            let (base_reg, list) = match (insn.operands[0], insn.operands[1]) {
                (Operand::Reg(b) | Operand::RegWBack(b, _), Operand::RegList(l)) => (b, l),
                (_, Operand::RegList(l)) if matches!(insn.opcode, Opcode::POP) => {
                    (Reg::from_u8(13), l)
                }
                _ => unreachable!(),
            };
            if (list & (1 << 15)) == 0 {
                return Ok(fallthrough);
            }

            let base_addr = regs.reg(base_reg);
            let before_pc = (list & 0x7FFF).count_ones();
            let total_regs = list.count_ones();

            // Opcode::LDM(add, pre, false, usermode)
            let pc_addr = match insn.opcode {
                // Increment After / pop
                Opcode::LDM(true, false, _, _) | Opcode::POP => {
                    base_addr.wrapping_add(before_pc * 4)
                }
                // Increment Before
                Opcode::LDM(true, true, _, _) => base_addr.wrapping_add((before_pc + 1) * 4),
                // Decrement After
                Opcode::LDM(false, false, _, _) => {
                    base_addr.wrapping_sub((total_regs - 1 - before_pc) * 4)
                }
                // Decrement Before
                Opcode::LDM(false, true, _, _) => {
                    base_addr.wrapping_sub((total_regs - before_pc) * 4)
                }
                _ => unreachable!(),
            };

            let target = mem.read_u32(pc_addr)?;
            Ok((target & !1, (target & 1) == 1))
        }
        Opcode::TBB => {
            let (base_val, index_val) = table_branch_address(&insn.operands, regs);
            let address = base_val.wrapping_add(index_val);
            let offset = mem.read_u8(address)? as u32;
            return Ok((regs.pc.wrapping_add(offset << 1), insn.thumb));
        }
        Opcode::TBH => {
            let (base_val, index_val) = table_branch_address(&insn.operands, regs);
            let address = base_val.wrapping_add(index_val << 2);
            let offset = mem.read_u16(address)? as u32;
            return Ok((regs.pc.wrapping_add(offset << 1), insn.thumb));
        }
        _ => Ok(fallthrough),
    }
}

fn thumb_branch_target(condition: ConditionCode, offset: i32, regs: &RegContext) -> u32 {
    let base = if condition == ConditionCode::AL {
        regs.pc.wrapping_add(4)
    } else {
        regs.pc.wrapping_sub(4)
    };
    base.wrapping_add((offset << 1) as u32)
}

fn is_pc_destination(operand: Operand) -> bool {
    matches!(operand, Operand::Reg(reg) if reg.number() == 15)
}

fn value_of(operand: Operand, regs: &RegContext) -> u32 {
    match operand {
        Operand::Reg(reg) => regs.reg(reg),
        Operand::Imm12(value) => value as u32,
        Operand::Imm32(value) => value,
        _ => unreachable!(),
    }
}

fn eval_alu(opcode: &Opcode, operands: &[Operand; 4], regs: &RegContext) -> u32 {
    let first = value_of(operands[1], regs);
    let (_, _, carry, _) = regs.cond_flags();
    let carry = if carry { 1 } else { 0 };

    match opcode {
        Opcode::MOV | Opcode::ADR => first,
        Opcode::MVN => !first,
        Opcode::RRX => (first >> 1) | (carry << 31),
        _ => {
            let second = value_of(operands[2], regs);
            let shift = second & 0xFF;
            match opcode {
                Opcode::ADD => first.wrapping_add(second),
                Opcode::ADC => first.wrapping_add(second).wrapping_add(carry),
                Opcode::SUB => first.wrapping_sub(second),
                Opcode::RSB => second.wrapping_sub(first),
                Opcode::SBC => first.wrapping_sub(second).wrapping_sub(1 - carry),
                Opcode::RSC => second.wrapping_sub(first).wrapping_sub(1 - carry),
                Opcode::AND => first & second,
                Opcode::EOR => first ^ second,
                Opcode::ORR => first | second,
                Opcode::BIC => first & !second,
                Opcode::LSL => match shift {
                    0 => first,
                    1..=31 => first << shift,
                    _ => 0,
                },
                Opcode::LSR => match shift {
                    0 => first,
                    1..=31 => first >> shift,
                    _ => 0,
                },
                Opcode::ASR => match shift {
                    0 => first,
                    1..=31 => ((first as i32) >> shift) as u32,
                    _ if (first & (1 << 31)) != 0 => 0xFFFFFFFF,
                    _ => 0,
                },
                Opcode::ROR => match shift & 31 {
                    0 => first,
                    s => first.rotate_right(s),
                },
                _ => unreachable!(),
            }
        }
    }
}

fn eval_cond(cond: ConditionCode, regs: &RegContext) -> bool {
    let (n, z, c, v) = regs.cond_flags();
    match cond {
        ConditionCode::EQ => z,
        ConditionCode::NE => !z,
        ConditionCode::HS => c,
        ConditionCode::LO => !c,
        ConditionCode::MI => n,
        ConditionCode::PL => !n,
        ConditionCode::VS => v,
        ConditionCode::VC => !v,
        ConditionCode::HI => c && !z,
        ConditionCode::LS => !c || z,
        ConditionCode::GE => n == v,
        ConditionCode::LT => n != v,
        ConditionCode::GT => !z && (n == v),
        ConditionCode::LE => z || (n != v),
        ConditionCode::AL => true,
    }
}

fn effective_address(operand: Operand, regs: &RegContext) -> u32 {
    match operand {
        Operand::RegDeref(base) => regs.reg(base),
        Operand::RegDerefPreindexOffset(base, offset, add, _) => {
            if add {
                regs.reg(base).wrapping_add(offset as u32)
            } else {
                regs.reg(base).wrapping_sub(offset as u32)
            }
        }
        Operand::RegDerefPostindexOffset(base, _, _, _) => regs.reg(base),
        _ => unreachable!(),
    }
}

fn table_branch_address(operands: &[Operand; 4], regs: &RegContext) -> (u32, u32) {
    let (base, index) = match (operands[0], operands[1]) {
        (Operand::Reg(base), Operand::Reg(index)) => (base, index),
        (Operand::RegDerefPreindexReg(base, index, _, _), Operand::Nothing) => (base, index),
        _ => unreachable!(),
    };

    let base_val = regs.reg(base);
    let index_val = regs.reg(index);
    (base_val, index_val)
}
