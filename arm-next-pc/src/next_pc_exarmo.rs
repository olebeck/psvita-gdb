use exarmo_aarch32::{
    Amode, BranchKind, Cond, Encoding, GpReg, Instruction, ItState, Mem, Mnemonic, Modifier,
    ModifierKind, Offset, Operand, PcRead, Reg, Writeback, a32, t32,
};

use crate::{MemReader, NextPcError, RegContext};

pub fn next_pc<Mem: MemReader>(regs: &RegContext, mem: &Mem) -> Result<(u32, bool), NextPcError> {
    let thumb = regs.thumb();
    let addr = if thumb {
        regs.pc.wrapping_sub(4)
    } else {
        regs.pc.wrapping_sub(8)
    };

    let (insn, length) = decode_insn(regs, mem, addr)?;
    let fallthrough = (addr.wrapping_add(length), thumb);
    let ops = insn.operands();
    let ops = ops.as_slice();

    if thumb {
        let state = it_state(regs);
        if state.in_block() && !eval_cond(state.condition(), regs) {
            return Ok(fallthrough);
        }
    }

    if let Some(cond) = find_cond(ops) {
        if !eval_cond(cond, regs) {
            return Ok(fallthrough);
        }
    }

    let branch = insn.at(addr as u64).branch();

    match insn.mnemonic() {
        Mnemonic::Cbz => {
            let taken = arg_reg(ops, 0).is_some_and(|reg| reg_value(reg, regs) == 0);
            return Ok(if taken {
                (branch.target.unwrap_or(fallthrough.0 as u64) as u32, thumb)
            } else {
                fallthrough
            });
        }
        Mnemonic::Cbnz => {
            let taken = arg_reg(ops, 0).is_some_and(|reg| reg_value(reg, regs) != 0);
            return Ok(if taken {
                (branch.target.unwrap_or(fallthrough.0 as u64) as u32, thumb)
            } else {
                fallthrough
            });
        }
        _ => {}
    }

    match branch.kind {
        BranchKind::Direct | BranchKind::DirectCall => {
            let target = direct_target(&insn, ops, &branch, addr, fallthrough.0);
            let target_thumb = if insn.mnemonic() == Mnemonic::Blx {
                !thumb
            } else {
                thumb
            };
            Ok((target, target_thumb))
        }
        BranchKind::Indirect | BranchKind::IndirectCall | BranchKind::ExceptionReturn => {
            indirect_target(&insn, ops, regs, mem, addr, branch.kind)
                .map(|target| target.unwrap_or(fallthrough))
        }
        _ => Ok(fallthrough),
    }
}

fn decode_insn<Mem: MemReader>(
    regs: &RegContext,
    mem: &Mem,
    addr: u32,
) -> Result<(Instruction, u32), NextPcError> {
    if regs.thumb() {
        let first = mem.read_u16(addr)?;
        let length = t32::length(first);
        let bits = match length {
            4 => (u32::from(first) << 16) | u32::from(mem.read_u16(addr.wrapping_add(2))?),
            _ => u32::from(first) << 16,
        };
        let insn = t32::decode_word(bits, it_state(regs)).map_err(|_| NextPcError::DecodeError)?;
        Ok((insn, u32::from(length)))
    } else {
        let bits = mem.read_u32(addr)?;
        let insn = a32::decode_word(bits).map_err(|_| NextPcError::DecodeError)?;
        Ok((insn, 4))
    }
}

fn direct_target(
    insn: &Instruction,
    ops: &[Operand],
    branch: &exarmo_aarch32::Branch,
    addr: u32,
    fallthrough: u32,
) -> u32 {
    if insn.encoding() == Encoding::BT2 {
        let offset = find_label(ops).unwrap_or(0);
        return addr.wrapping_add(4).wrapping_add((offset / 2) as u32);
    }

    branch.target.unwrap_or(fallthrough as u64) as u32
}

fn indirect_target<Mem: MemReader>(
    insn: &Instruction,
    ops: &[Operand],
    regs: &RegContext,
    mem: &Mem,
    addr: u32,
    kind: BranchKind,
) -> Result<Option<(u32, bool)>, NextPcError> {
    match insn.mnemonic() {
        Mnemonic::Bx | Mnemonic::Bxj | Mnemonic::Blx => {
            let Some(reg) = arg_reg(ops, 0) else {
                return Ok(None);
            };
            let value = reg_value(reg, regs);
            Ok(Some((value & !1, value & 1 == 1)))
        }
        Mnemonic::Tbb => {
            let Some(mem_operand) = arg_mem(ops, 0) else {
                return Ok(None);
            };
            let offset = mem.read_u8(mem_address(mem_operand, regs, regs.thumb()))? as u32;
            Ok(Some((regs.pc.wrapping_add(offset << 1), true)))
        }
        Mnemonic::Tbh => {
            let Some(mem_operand) = arg_mem(ops, 0) else {
                return Ok(None);
            };
            let offset = mem.read_u16(mem_address(mem_operand, regs, regs.thumb()))? as u32;
            Ok(Some((regs.pc.wrapping_add(offset << 1), true)))
        }
        Mnemonic::Ldm | Mnemonic::Ldmda | Mnemonic::Ldmdb | Mnemonic::Ldmib | Mnemonic::Pop => {
            load_multiple_target(insn, ops, regs, mem)
        }
        Mnemonic::Rfe | Mnemonic::Rfeda | Mnemonic::Rfedb | Mnemonic::Rfeib => {
            rfe_target(insn, ops, regs, mem)
        }
        Mnemonic::Ldr | Mnemonic::Ldrt => load_register_target(ops, regs, mem, addr),
        Mnemonic::Adr
        | Mnemonic::Add
        | Mnemonic::Adds
        | Mnemonic::Adc
        | Mnemonic::Adcs
        | Mnemonic::Sub
        | Mnemonic::Subs
        | Mnemonic::Sbc
        | Mnemonic::Sbcs
        | Mnemonic::Rsb
        | Mnemonic::Rsbs
        | Mnemonic::Rsc
        | Mnemonic::Rscs
        | Mnemonic::And
        | Mnemonic::Ands
        | Mnemonic::Eor
        | Mnemonic::Eors
        | Mnemonic::Orr
        | Mnemonic::Orrs
        | Mnemonic::Bic
        | Mnemonic::Bics
        | Mnemonic::Mov
        | Mnemonic::Movs
        | Mnemonic::Mvn
        | Mnemonic::Mvns
        | Mnemonic::Lsl
        | Mnemonic::Lsls
        | Mnemonic::Lsr
        | Mnemonic::Lsrs
        | Mnemonic::Asr
        | Mnemonic::Asrs
        | Mnemonic::Ror
        | Mnemonic::Rors
        | Mnemonic::Rrx
        | Mnemonic::Rrxs => {
            let target = eval_alu(insn, ops, regs, addr);
            let exception_return = kind == BranchKind::ExceptionReturn;
            Ok(Some(alu_target(target, regs, exception_return)))
        }
        _ => Ok(None),
    }
}

fn load_register_target<Mem: MemReader>(
    ops: &[Operand],
    regs: &RegContext,
    mem: &Mem,
    addr: u32,
) -> Result<Option<(u32, bool)>, NextPcError> {
    let Some(destination) = arg_reg(ops, 0) else {
        return Ok(None);
    };
    if destination.num() != 15 {
        return Ok(None);
    }

    let address = match arg(ops, 1) {
        Some(Operand::Label { offset, pc }) => label_address(pc, addr, offset),
        Some(Operand::Mem(operand)) => mem_address(operand, regs, regs.thumb()),
        _ => return Ok(None),
    };
    let target = mem.read_u32(address)?;
    Ok(Some((target & !1, target & 1 == 1)))
}

fn load_multiple_target<Mem: MemReader>(
    insn: &Instruction,
    ops: &[Operand],
    regs: &RegContext,
    mem: &Mem,
) -> Result<Option<(u32, bool)>, NextPcError> {
    let Some(list) = find_list(ops) else {
        return Ok(None);
    };
    if list.mask & (1 << 15) == 0 {
        return Ok(None);
    }

    let base_reg = find_reg(ops).unwrap_or(Reg::Core(GpReg::new(13)));
    let base = reg_value(base_reg, regs);
    let amode = match insn.encoding() {
        Encoding::LdmA1
        | Encoding::LdmT1
        | Encoding::LdmT2
        | Encoding::PopLdmA1
        | Encoding::PopLdmT2
        | Encoding::PopT1 => Amode::Ia,
        Encoding::LdmibA1 => Amode::Ib,
        Encoding::LdmdaA1 => Amode::Da,
        Encoding::LdmdbA1 | Encoding::LdmdbT1 => Amode::Db,
        Encoding::LdmEA1As => find_symbol(ops)
            .and_then(|bits| Amode::from_bits(bits as u8))
            .unwrap_or(Amode::Ia),
        _ => return Ok(None),
    };

    let before_pc = (list.mask & 0x7fff).count_ones();
    let total = list.mask.count_ones();
    let pc_address = match amode {
        Amode::Ia => base.wrapping_add(before_pc * 4),
        Amode::Ib => base.wrapping_add((before_pc + 1) * 4),
        Amode::Da => base.wrapping_sub((total - 1 - before_pc) * 4),
        Amode::Db => base.wrapping_sub((total - before_pc) * 4),
    };

    let target = mem.read_u32(pc_address)?;
    if insn.encoding() == Encoding::LdmEA1As {
        let thumb = regs.spsr & (1 << 5) != 0;
        Ok(Some((target & if thumb { !1 } else { !3 }, thumb)))
    } else {
        Ok(Some((target & !1, target & 1 == 1)))
    }
}

fn rfe_target<Mem: MemReader>(
    insn: &Instruction,
    ops: &[Operand],
    regs: &RegContext,
    mem: &Mem,
) -> Result<Option<(u32, bool)>, NextPcError> {
    let Some(base_reg) = find_reg(ops) else {
        return Ok(None);
    };
    let base = reg_value(base_reg, regs);
    let first_address = match insn.encoding() {
        Encoding::RfeiaA1As | Encoding::RfeT2As => base,
        Encoding::RfeibA1As => base.wrapping_add(4),
        Encoding::RfedaA1As => base.wrapping_sub(4),
        Encoding::RfedbA1As | Encoding::RfeT1As => base.wrapping_sub(8),
        _ => return Ok(None),
    };

    let target = mem.read_u32(first_address)?;
    let cpsr = mem.read_u32(first_address.wrapping_add(4))?;
    let thumb = cpsr & (1 << 5) != 0;
    Ok(Some((target & if thumb { !1 } else { !3 }, thumb)))
}

fn eval_alu(insn: &Instruction, ops: &[Operand], regs: &RegContext, addr: u32) -> u32 {
    let carry = u32::from(regs.cpsr & (1 << 29) != 0);

    match insn.mnemonic() {
        Mnemonic::Mov | Mnemonic::Movs => operand_value(arg(ops, 1), regs, addr),
        Mnemonic::Mvn | Mnemonic::Mvns => !operand_value(arg(ops, 1), regs, addr),
        Mnemonic::Rrx | Mnemonic::Rrxs => rrx(operand_value(arg(ops, 1), regs, addr), carry),
        Mnemonic::Lsl | Mnemonic::Lsls => shift_alias(ops, regs, ModifierKind::Lsl),
        Mnemonic::Lsr | Mnemonic::Lsrs => shift_alias(ops, regs, ModifierKind::Lsr),
        Mnemonic::Asr | Mnemonic::Asrs => shift_alias(ops, regs, ModifierKind::Asr),
        Mnemonic::Ror | Mnemonic::Rors => shift_alias(ops, regs, ModifierKind::Ror),
        Mnemonic::Adr => operand_value(arg(ops, 1), regs, addr),
        Mnemonic::Add | Mnemonic::Adds => operand_value(arg(ops, 1), regs, addr)
            .wrapping_add(operand_value(arg(ops, 2), regs, addr)),
        Mnemonic::Adc | Mnemonic::Adcs => operand_value(arg(ops, 1), regs, addr)
            .wrapping_add(operand_value(arg(ops, 2), regs, addr))
            .wrapping_add(carry),
        Mnemonic::Sub | Mnemonic::Subs => operand_value(arg(ops, 1), regs, addr)
            .wrapping_sub(operand_value(arg(ops, 2), regs, addr)),
        Mnemonic::Sbc | Mnemonic::Sbcs => operand_value(arg(ops, 1), regs, addr)
            .wrapping_sub(operand_value(arg(ops, 2), regs, addr))
            .wrapping_sub(1 - carry),
        Mnemonic::Rsb | Mnemonic::Rsbs => operand_value(arg(ops, 2), regs, addr)
            .wrapping_sub(operand_value(arg(ops, 1), regs, addr)),
        Mnemonic::Rsc | Mnemonic::Rscs => operand_value(arg(ops, 2), regs, addr)
            .wrapping_sub(operand_value(arg(ops, 1), regs, addr))
            .wrapping_sub(1 - carry),
        Mnemonic::And | Mnemonic::Ands => {
            operand_value(arg(ops, 1), regs, addr) & operand_value(arg(ops, 2), regs, addr)
        }
        Mnemonic::Eor | Mnemonic::Eors => {
            operand_value(arg(ops, 1), regs, addr) ^ operand_value(arg(ops, 2), regs, addr)
        }
        Mnemonic::Orr | Mnemonic::Orrs => {
            operand_value(arg(ops, 1), regs, addr) | operand_value(arg(ops, 2), regs, addr)
        }
        Mnemonic::Bic | Mnemonic::Bics => {
            operand_value(arg(ops, 1), regs, addr) & !operand_value(arg(ops, 2), regs, addr)
        }
        _ => 0,
    }
}

fn shift_alias(ops: &[Operand], regs: &RegContext, kind: ModifierKind) -> u32 {
    if positional_len(ops) >= 3 {
        let value = operand_value(arg(ops, 1), regs, 0);
        let (amount, register_shift) = shift_amount(arg(ops, 2), regs);
        shift(value, kind, amount, register_shift, regs)
    } else {
        let value = operand_value(arg(ops, 0), regs, 0);
        let (amount, register_shift) = shift_amount(arg(ops, 1), regs);
        shift(value, kind, amount, register_shift, regs)
    }
}

fn alu_target(target: u32, regs: &RegContext, exception_return: bool) -> (u32, bool) {
    if exception_return {
        let thumb = regs.spsr & (1 << 5) != 0;
        (target & if thumb { !1 } else { !3 }, thumb)
    } else if regs.thumb() {
        (target & !1, true)
    } else {
        (target & !1, target & 1 == 1)
    }
}

fn operand_value(operand: Option<Operand>, regs: &RegContext, addr: u32) -> u32 {
    match operand {
        Some(Operand::Reg(operand)) => register_operand_value(operand.reg, operand.modifier, regs),
        Some(Operand::Imm { value, modifier }) => {
            let value = value as u32;
            match modifier {
                Some(modifier) => apply_modifier(value, modifier, regs),
                None => value,
            }
        }
        Some(Operand::Label { offset, pc }) => label_address(pc, addr, offset),
        Some(Operand::List(list)) => list.mask,
        _ => 0,
    }
}

fn register_operand_value(reg: Reg, modifier: Option<Modifier>, regs: &RegContext) -> u32 {
    let value = reg_value(reg, regs);
    match modifier {
        Some(modifier) => apply_modifier(value, modifier, regs),
        None => value,
    }
}

fn apply_modifier(value: u32, modifier: Modifier, regs: &RegContext) -> u32 {
    let register_shift = modifier.by.is_some();
    let amount = match modifier.amount {
        Some(amount) => amount,
        None => modifier
            .by
            .map(|reg| reg_value(Reg::Core(reg), regs) & 0xff)
            .unwrap_or(0),
    };
    shift(value, modifier.kind, amount, register_shift, regs)
}

fn shift(
    value: u32,
    kind: ModifierKind,
    amount: u32,
    register_shift: bool,
    regs: &RegContext,
) -> u32 {
    match kind {
        ModifierKind::Lsl if amount == 0 => value,
        ModifierKind::Lsl if amount < 32 => value << amount,
        ModifierKind::Lsl => 0,
        ModifierKind::Lsr if amount == 0 && register_shift => value,
        ModifierKind::Lsr if amount < 32 => value >> amount,
        ModifierKind::Lsr => 0,
        ModifierKind::Asr if amount == 0 && register_shift => value,
        ModifierKind::Asr if amount < 32 => ((value as i32) >> amount) as u32,
        ModifierKind::Asr => ((value as i32) >> 31) as u32,
        ModifierKind::Ror if amount == 0 && register_shift => value,
        ModifierKind::Ror => value.rotate_right(amount & 31),
        ModifierKind::Rrx => {
            let carry = u32::from(regs.cpsr & (1 << 29) != 0);
            rrx(value, carry)
        }
    }
}

fn rrx(value: u32, carry: u32) -> u32 {
    (value >> 1) | (carry << 31)
}

fn shift_amount(operand: Option<Operand>, regs: &RegContext) -> (u32, bool) {
    match operand {
        Some(Operand::Reg(operand)) => (reg_value(operand.reg, regs) & 0xff, true),
        Some(Operand::Imm { value, .. }) => (value as u32, false),
        _ => (0, false),
    }
}

fn label_address(pc: PcRead, addr: u32, offset: i64) -> u32 {
    pc.target(addr as u64, offset, 32) as u32
}

fn mem_address(mem: Mem, regs: &RegContext, thumb: bool) -> u32 {
    let base = reg_value(mem.base, regs);
    let base = if thumb && mem.base.num() == 15 {
        base & !3
    } else {
        base
    };

    if mem.writeback == Writeback::Post {
        return base;
    }

    match mem.offset {
        Offset::None => base,
        Offset::Imm { value, .. } => base.wrapping_add(value as u32),
        Offset::Reg {
            reg,
            subtract,
            modifier,
        } => {
            let value = match modifier {
                Some(modifier) => apply_modifier(reg_value(reg, regs), modifier, regs),
                None => reg_value(reg, regs),
            };
            if subtract {
                base.wrapping_sub(value)
            } else {
                base.wrapping_add(value)
            }
        }
    }
}

fn reg_value(reg: Reg, regs: &RegContext) -> u32 {
    match reg {
        Reg::Core(_) => regs.reg(reg.num()),
        _ => 0,
    }
}

fn arg(ops: &[Operand], mut index: usize) -> Option<Operand> {
    for &operand in ops {
        if matches!(operand, Operand::Cond(_)) {
            continue;
        }
        if index == 0 {
            return Some(operand);
        }
        index -= 1;
    }
    None
}

fn positional_len(ops: &[Operand]) -> usize {
    ops.iter()
        .filter(|operand| !matches!(operand, Operand::Cond(_)))
        .count()
}

fn arg_reg(ops: &[Operand], index: usize) -> Option<Reg> {
    match arg(ops, index) {
        Some(Operand::Reg(operand)) => Some(operand.reg),
        _ => None,
    }
}

fn arg_mem(ops: &[Operand], index: usize) -> Option<Mem> {
    match arg(ops, index) {
        Some(Operand::Mem(mem)) => Some(mem),
        _ => None,
    }
}

fn find_cond(ops: &[Operand]) -> Option<Cond> {
    ops.iter().find_map(|operand| match operand {
        Operand::Cond(cond) => Some(*cond),
        _ => None,
    })
}

fn find_label(ops: &[Operand]) -> Option<i64> {
    ops.iter().find_map(|operand| match operand {
        Operand::Label { offset, .. } => Some(*offset),
        _ => None,
    })
}

fn find_list(ops: &[Operand]) -> Option<exarmo_aarch32::RegList> {
    ops.iter().find_map(|operand| match operand {
        Operand::List(list) => Some(*list),
        _ => None,
    })
}

fn find_reg(ops: &[Operand]) -> Option<Reg> {
    ops.iter().find_map(|operand| match operand {
        Operand::Reg(operand) => Some(operand.reg),
        _ => None,
    })
}

fn find_symbol(ops: &[Operand]) -> Option<u16> {
    ops.iter().find_map(|operand| match operand {
        Operand::Symbol(symbol) => Some(symbol.bits),
        _ => None,
    })
}

fn eval_cond(cond: Cond, regs: &RegContext) -> bool {
    let (n, z, c, v) = regs.cond_flags();
    match cond {
        Cond::Eq => z,
        Cond::Ne => !z,
        Cond::Cs => c,
        Cond::Cc => !c,
        Cond::Mi => n,
        Cond::Pl => !n,
        Cond::Vs => v,
        Cond::Vc => !v,
        Cond::Hi => c && !z,
        Cond::Ls => !c || z,
        Cond::Ge => n == v,
        Cond::Lt => n != v,
        Cond::Gt => !z && (n == v),
        Cond::Le => z || (n != v),
        Cond::Al => true,
    }
}

fn it_state(regs: &RegContext) -> ItState {
    if !regs.thumb() {
        return ItState::Outside;
    }
    let bits = ((regs.cpsr >> 8) & 0xfc) | ((regs.cpsr >> 25) & 0x03);
    ItState::from_bits(bits as u8)
}
