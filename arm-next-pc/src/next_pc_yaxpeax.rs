use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv7::{
    DecodeError, InstDecoder, Instruction, Opcode, Operand, Reg, RegShift, RegShiftStyle,
    ShiftStyle,
};

use crate::{MemReader, NextPcError, RegContext};

fn read_insn<Mem: MemReader>(
    regs: &RegContext,
    mem: &Mem,
    addr: u32,
) -> Result<([u8; 4], usize), NextPcError> {
    let mut bytes: [u8; 4] = [0u8; 4];
    let instruction_len = if regs.thumb() {
        mem.read(addr as usize, &mut bytes[..2])
            .ok_or(NextPcError::MemoryRead)?;
        let first_halfword = u16::from_le_bytes([bytes[0], bytes[1]]);
        if matches!(first_halfword >> 11, 0b11101..=0b11111) {
            mem.read(addr.wrapping_add(2) as usize, &mut bytes[2..])
                .ok_or(NextPcError::MemoryRead)?;
            4
        } else {
            2
        }
    } else {
        mem.read(addr as usize, &mut bytes)
            .ok_or(NextPcError::MemoryRead)?;
        4
    };
    Ok((bytes, instruction_len))
}

pub fn next_pc<Mem: MemReader>(regs: &RegContext, mem: &Mem) -> Result<(u32, bool), NextPcError> {
    let addr = if regs.thumb() {
        regs.pc.wrapping_sub(4)
    } else {
        regs.pc.wrapping_sub(8)
    };

    let (bytes, instruction_len) = read_insn(regs, mem, addr)?;

    let decoder = if regs.thumb() {
        InstDecoder::default_thumb()
    } else {
        InstDecoder::default()
    };
    let mut reader = U8Reader::new(&bytes[..instruction_len]);
    let insn = decoder
        .decode(&mut reader)
        .map_err(|_| NextPcError::DecodeError)?;

    let fallthrough = (
        addr.wrapping_add(if insn.thumb && !insn.wide { 2 } else { 4 }),
        insn.thumb,
    );

    if insn.thumb && !eval_it(regs) {
        return Ok(fallthrough);
    }

    if !eval_cond(insn.condition as u8, regs) {
        return Ok(fallthrough);
    }

    match insn.opcode {
        Opcode::B | Opcode::BL => match insn.operands[0] {
            Operand::BranchOffset(offset) => {
                Ok((regs.pc.wrapping_add(((offset - 2) << 2) as u32), false))
            }
            Operand::BranchThumbOffset(offset) => Ok((regs.pc.wrapping_add(offset as u32), true)),
            _ => unreachable!(),
        },
        Opcode::BLX => match insn.operands[0] {
            Operand::BranchOffset(offset) => Ok((regs.pc.wrapping_add((offset << 2) as u32), true)),
            Operand::BranchThumbOffset(offset) => {
                Ok(((regs.pc & !3).wrapping_add(offset as u32), !insn.thumb))
            }
            Operand::Reg(reg) => {
                let value = regs.reg(reg.number());
                return Ok((value & !1, value & 1 == 1));
            }
            _ => unreachable!(),
        },
        Opcode::BX | Opcode::BXJ => match insn.operands[0] {
            Operand::Reg(reg) => {
                let value = regs.reg(reg.number());
                return Ok((value & !1, value & 1 == 1));
            }
            _ => unreachable!(),
        },
        Opcode::CBZ => match (insn.operands[0], insn.operands[1]) {
            (Operand::Reg(reg), Operand::BranchThumbOffset(offset)) => {
                debug_assert!(insn.thumb);
                if regs.reg(reg.number()) == 0 {
                    // CBZ offset is += 1 in yaxpeax
                    return Ok((regs.pc.wrapping_add(((offset - 1) << 1) as u32), true));
                }
                return Ok(fallthrough);
            }
            _ => unreachable!(),
        },
        Opcode::CBNZ => match (insn.operands[0], insn.operands[1]) {
            (Operand::Reg(reg), Operand::BranchThumbOffset(offset)) => {
                debug_assert!(insn.thumb);
                if regs.reg(reg.number()) != 0 {
                    // CBZ offset is += 1 in yaxpeax
                    return Ok((regs.pc.wrapping_add(((offset - 1) << 1) as u32), true));
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
        | Opcode::ADR(_) => {
            if !is_pc_destination(insn.operands[0]) {
                return Ok(fallthrough);
            }
            let target = eval_alu(&insn, regs);
            return if insn.s {
                let thumb = regs.spsr & (1 << 5) != 0;
                Ok((target & if thumb { !1 } else { !3 }, thumb))
            } else if insn.thumb {
                Ok((target & !1, true))
            } else {
                Ok((target & !1, target & 1 == 1))
            };
        }
        Opcode::LDR | Opcode::LDRT => {
            if !is_pc_destination(insn.operands[0]) {
                return Ok(fallthrough);
            }
            let address = effective_address(insn.operands[1], regs, insn.thumb);
            let target = mem.read_u32(address)?;
            return Ok((target & !1, target & 1 == 1));
        }
        Opcode::LDM(_, _, _, _) | Opcode::POP => {
            let (base_reg, list) = match (insn.operands[0], insn.operands[1]) {
                (Operand::Reg(b) | Operand::RegWBack(b, _), Operand::RegList(l)) => (b, l),
                (Operand::RegList(l), _) if matches!(insn.opcode, Opcode::POP) => {
                    (Reg::from_u8(13), l)
                }
                _ => unreachable!(),
            };
            if (list & (1 << 15)) == 0 {
                return Ok(fallthrough);
            }
            let exception_return = matches!(insn.opcode, Opcode::LDM(_, _, _, true));

            let base_addr = regs.reg(base_reg.number());
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
            if exception_return {
                let thumb = regs.spsr & (1 << 5) != 0;
                Ok((target & if thumb { !1 } else { !3 }, thumb))
            } else {
                Ok((target & !1, target & 1 == 1))
            }
        }
        Opcode::TBB => {
            debug_assert!(insn.thumb);
            let (base_val, index_val) = table_branch_address(&insn.operands, regs);
            let address = base_val.wrapping_add(index_val);
            let offset = mem.read_u8(address)? as u32;
            return Ok((regs.pc.wrapping_add(offset << 1), true));
        }
        Opcode::TBH => {
            debug_assert!(insn.thumb);
            let (base_val, index_val) = table_branch_address(&insn.operands, regs);
            let address = base_val.wrapping_add(index_val << 1);
            let offset = mem.read_u16(address)? as u32;
            return Ok((regs.pc.wrapping_add(offset << 1), true));
        }
        Opcode::RFE(pre, add) => {
            let base = match insn.operands[0] {
                Operand::Reg(reg) | Operand::RegWBack(reg, _) => regs.reg(reg.number()),
                _ => unreachable!(),
            };
            let first_address = match (pre, add) {
                (false, true) => base,
                (true, true) => base.wrapping_add(4),
                (false, false) => base.wrapping_sub(4),
                (true, false) => base.wrapping_sub(8),
            };
            let target = mem.read_u32(first_address)?;
            let cpsr = mem.read_u32(first_address.wrapping_add(4))?;
            let thumb = cpsr & (1 << 5) != 0;
            Ok((target & if thumb { !1 } else { !3 }, thumb))
        }
        _ => Ok(fallthrough),
    }
}

fn is_pc_destination(operand: Operand) -> bool {
    matches!(operand, Operand::Reg(reg) if reg.number() == 15)
}

fn value_of(operand: Operand, regs: &RegContext, thumb: bool) -> u32 {
    match operand {
        Operand::Reg(reg) | Operand::RegWBack(reg, _) => regs.reg(reg.number()),
        Operand::RegShift(shift) => shifted_register(shift, regs),
        Operand::Imm12(value) => value as u32,
        Operand::Imm32(value) => value,
        Operand::Nothing => 0,
        Operand::RegDeref(reg) => memory_base(reg, regs, thumb),
        Operand::RegDerefPreindexOffset(reg, offset, add, _) => {
            add_offset(memory_base(reg, regs, thumb), offset as u32, add)
        }
        Operand::RegDerefPostindexOffset(reg, _, _, _)
        | Operand::RegDerefPostindexReg(reg, _, _, _)
        | Operand::RegDerefPostindexRegShift(reg, _, _, _) => memory_base(reg, regs, thumb),
        Operand::RegDerefPreindexReg(reg, offset, add, _) => add_offset(
            memory_base(reg, regs, thumb),
            regs.reg(offset.number()),
            add,
        ),
        Operand::RegDerefPreindexRegShift(reg, offset, add, _) => add_offset(
            memory_base(reg, regs, thumb),
            shifted_register(offset, regs),
            add,
        ),
        Operand::RegList(list) => list as u32,
        Operand::BranchOffset(offset) | Operand::BranchThumbOffset(offset) => offset as u32,
        _ => unreachable!(),
    }
}

fn eval_alu(insn: &Instruction, regs: &RegContext) -> u32 {
    let first = value_of(insn.operands[1], regs, insn.thumb);
    let (_, _, carry, _) = regs.cond_flags();
    let carry = if carry { 1 } else { 0 };

    match insn.opcode {
        Opcode::MOV => first,
        Opcode::ADR(subtract) => match insn.operands[1] {
            Operand::Reg(reg) if reg.number() == 15 => {
                let base = if insn.thumb { regs.pc & !3 } else { regs.pc };
                let offset = value_of(insn.operands[2], regs, insn.thumb);
                if subtract {
                    base.wrapping_sub(offset)
                } else {
                    base.wrapping_add(offset)
                }
            }
            _ => {
                let base = if insn.thumb { regs.pc & !3 } else { regs.pc };
                base.wrapping_add(first)
            }
        },
        Opcode::MVN => !first,
        Opcode::RRX => (first >> 1) | (carry << 31),
        _ => {
            let second = value_of(insn.operands[2], regs, insn.thumb);
            let shift = second & 0xFF;
            match insn.opcode {
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
                _ => unreachable!("eval_alu called with non-ALU opcode"),
            }
        }
    }
}

fn eval_it(regs: &RegContext) -> bool {
    let itstate = ((regs.cpsr >> 8) & 0xFC) | ((regs.cpsr >> 25) & 0x03);
    if itstate & 0x0F != 0 {
        eval_cond((itstate >> 4) as u8, regs)
    } else {
        true
    }
}

fn eval_cond(cond: u8, regs: &RegContext) -> bool {
    let (n, z, c, v) = regs.cond_flags();
    match cond {
        0 => z,
        1 => !z,
        2 => c,
        3 => !c,
        4 => n,
        5 => !n,
        6 => v,
        7 => !v,
        8 => c && !z,
        9 => !c || z,
        10 => n == v,
        11 => n != v,
        12 => !z && (n == v),
        13 => z || (n != v),
        14 => true,
        _ => false,
    }
}

fn effective_address(operand: Operand, regs: &RegContext, thumb: bool) -> u32 {
    match operand {
        Operand::RegDeref(base) => memory_base(base, regs, thumb),
        Operand::RegDerefPreindexOffset(base, offset, add, _) => {
            add_offset(memory_base(base, regs, thumb), offset as u32, add)
        }
        Operand::RegDerefPostindexOffset(base, _, _, _) => memory_base(base, regs, thumb),
        Operand::RegDerefPreindexReg(base, offset, add, _) => add_offset(
            memory_base(base, regs, thumb),
            regs.reg(offset.number()),
            add,
        ),
        Operand::RegDerefPostindexReg(base, _, _, _) => memory_base(base, regs, thumb),
        Operand::RegDerefPreindexRegShift(base, shift, add, _) => add_offset(
            memory_base(base, regs, thumb),
            shifted_register(shift, regs),
            add,
        ),
        Operand::RegDerefPostindexRegShift(base, _, _, _) => memory_base(base, regs, thumb),
        Operand::RegShift(shift) => shifted_register(shift, regs),
        _ => unreachable!("effective_address called with non-memory operand"),
    }
}

fn memory_base(reg: Reg, regs: &RegContext, thumb: bool) -> u32 {
    let base = regs.reg(reg.number());
    if thumb && reg.number() == 15 {
        base & !3
    } else {
        base
    }
}

fn add_offset(base: u32, offset: u32, add: bool) -> u32 {
    if add {
        base.wrapping_add(offset)
    } else {
        base.wrapping_sub(offset)
    }
}

fn shifted_register(shift: RegShift, regs: &RegContext) -> u32 {
    let (value, amount, style, register_shift) = match shift.into_shift() {
        RegShiftStyle::RegImm(shift) => (
            regs.reg(shift.shiftee().number()),
            shift.imm() as u32,
            shift.stype(),
            false,
        ),
        RegShiftStyle::RegReg(shift) => (
            regs.reg(shift.shiftee().number()),
            regs.reg(shift.shifter().number()) & 0xFF,
            shift.stype(),
            true,
        ),
    };

    match style {
        ShiftStyle::LSL if amount == 0 => value,
        ShiftStyle::LSL if amount < 32 => value << amount,
        ShiftStyle::LSL => 0,
        ShiftStyle::LSR if amount == 0 && register_shift => value,
        ShiftStyle::LSR if amount < 32 => value >> amount,
        ShiftStyle::LSR => 0,
        ShiftStyle::ASR if amount == 0 && register_shift => value,
        ShiftStyle::ASR if amount < 32 => ((value as i32) >> amount) as u32,
        ShiftStyle::ASR => ((value as i32) >> 31) as u32,
        ShiftStyle::ROR if amount == 0 && register_shift => value,
        ShiftStyle::ROR => value.rotate_right(amount & 31),
        ShiftStyle::RRX => {
            let carry = u32::from(regs.cpsr & (1 << 29) != 0);
            (value >> 1) | (carry << 31)
        }
    }
}

fn table_branch_address(operands: &[Operand; 4], regs: &RegContext) -> (u32, u32) {
    let (base, index) = match (operands[0], operands[1]) {
        (Operand::Reg(base), Operand::Reg(index)) => (base, index),
        (Operand::RegDerefPreindexReg(base, index, _, _), Operand::Nothing) => (base, index),
        (Operand::RegDerefPreindexRegShift(base, shift, _, _), Operand::Nothing) => {
            match shift.into_shift() {
                RegShiftStyle::RegImm(shift)
                    if shift.stype() == ShiftStyle::LSL && shift.imm() == 1 =>
                {
                    (base, shift.shiftee())
                }
                _ => unreachable!("TBH decoder returned an invalid index shift"),
            }
        }
        _ => unreachable!("table-branch decoder returned invalid operands"),
    };

    let base_val = regs.reg(base.number());
    let index_val = regs.reg(index.number());
    (base_val, index_val)
}
