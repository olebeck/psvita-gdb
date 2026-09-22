#[cfg(test)]
mod tests {
    use super::super::{MemReader, NextPcError, RegContext, next_pc};
    use asm_rs_macros::asm_bytes;

    struct TestMemory {
        regions: Vec<(usize, Vec<u8>)>,
    }

    impl TestMemory {
        fn new() -> Self {
            Self {
                regions: Vec::new(),
            }
        }

        fn add(&mut self, base: usize, bytes: &[u8]) {
            self.regions.push((base, bytes.to_vec()));
        }
    }

    impl MemReader for TestMemory {
        fn read(&self, addr: usize, buf: &mut [u8]) -> Option<()> {
            for (base, bytes) in &self.regions {
                let offset = addr.checked_sub(*base)?;
                let end = offset.checked_add(buf.len())?;

                if let Some(src) = bytes.get(offset..end) {
                    buf.copy_from_slice(src);
                    return Some(());
                }
            }

            None
        }
    }

    fn arm(bytes: &[u8], pc: u32) -> (RegContext, TestMemory) {
        println!(
            "bytes: {}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join("")
        );
        let mut memory = TestMemory::new();
        memory.add(pc as usize, bytes);

        (
            RegContext {
                pc: pc + 8,
                ..RegContext::default()
            },
            memory,
        )
    }

    fn thumb(bytes: &[u8], pc: u32) -> (RegContext, TestMemory) {
        println!(
            "bytes: {}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join("")
        );
        let mut instruction = [0u8; 4];
        instruction[..bytes.len()].copy_from_slice(bytes);

        let mut memory = TestMemory::new();
        memory.add(pc as usize, &instruction);

        (
            RegContext {
                pc: pc + 4,
                cpsr: 1 << 5,
                ..RegContext::default()
            },
            memory,
        )
    }

    // Fallthrough

    #[test]
    fn arm_fallthrough_is_next_instruction() {
        let bytes = asm_bytes!(arm, "mov r0, r0");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1004, false));
    }

    #[test]
    fn thumb_fallthrough_narrow_instruction() {
        let bytes = asm_bytes!(thumb, "movs r0, r0");
        let (regs, memory) = thumb(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1002, true));
    }

    #[test]
    fn thumb_fallthrough_wide_instruction() {
        let bytes = asm_bytes!(thumb, "bl #0");
        let (regs, memory) = thumb(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1004, true));
    }

    // ARM B / BL

    #[test]
    fn arm_b_forward() {
        let bytes = asm_bytes!(arm, "b #0x100");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_b_backward() {
        let bytes = asm_bytes!(arm, "b #-0x100");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1008 - 0x100, false));
    }

    #[test]
    fn arm_b_zero_offset() {
        let bytes = asm_bytes!(arm, "b #0");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1008, false));
    }

    #[test]
    fn arm_bl_forward() {
        let bytes = asm_bytes!(arm, "bl #0x100");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    // ARM conditional B

    #[test]
    fn arm_beq_taken_when_z_set() {
        let bytes = asm_bytes!(arm, "beq #0x100");
        let (mut regs, memory) = arm(bytes, 0x1000);

        regs.cpsr |= 1 << 30;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_beq_not_taken_when_z_clear() {
        let bytes = asm_bytes!(arm, "beq #0x100");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1004, false));
    }

    #[test]
    fn arm_bne_taken_when_z_clear() {
        let bytes = asm_bytes!(arm, "bne #0x100");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_bne_not_taken_when_z_set() {
        let bytes = asm_bytes!(arm, "bne #0x100");
        let (mut regs, memory) = arm(bytes, 0x1000);

        regs.cpsr |= 1 << 30;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1004, false));
    }

    #[test]
    fn arm_bcs_taken_when_c_set() {
        let bytes = asm_bytes!(arm, "bcs #0x100");
        let (mut regs, memory) = arm(bytes, 0x1000);

        regs.cpsr |= 1 << 29;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_bcc_taken_when_c_clear() {
        let bytes = asm_bytes!(arm, "bcc #0x100");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_bmi_taken_when_n_set() {
        let bytes = asm_bytes!(arm, "bmi #0x100");
        let (mut regs, memory) = arm(bytes, 0x1000);

        regs.cpsr |= 1 << 31;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_bpl_taken_when_n_clear() {
        let bytes = asm_bytes!(arm, "bpl #0x100");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_bvs_taken_when_v_set() {
        let bytes = asm_bytes!(arm, "bvs #0x100");
        let (mut regs, memory) = arm(bytes, 0x1000);

        regs.cpsr |= 1 << 28;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_bvc_taken_when_v_clear() {
        let bytes = asm_bytes!(arm, "bvc #0x100");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_bhi_requires_c_and_not_z() {
        let bytes = asm_bytes!(arm, "bhi #0x100");
        let (mut regs, memory) = arm(bytes, 0x1000);

        regs.cpsr |= 1 << 29;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));

        regs.cpsr |= 1 << 30;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1004, false));
    }

    #[test]
    fn arm_bls_requires_not_c_or_z() {
        let bytes = asm_bytes!(arm, "bls #0x100");
        let (mut regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));

        regs.cpsr |= 1 << 29;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1004, false));
    }

    #[test]
    fn arm_bge_uses_n_equals_v() {
        let bytes = asm_bytes!(arm, "bge #0x100");
        let (mut regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));

        regs.cpsr |= 1 << 31;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1004, false));

        regs.cpsr |= 1 << 28;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_blt_uses_n_not_equal_v() {
        let bytes = asm_bytes!(arm, "blt #0x100");
        let (mut regs, memory) = arm(bytes, 0x1000);

        regs.cpsr |= 1 << 31;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_bgt_requires_not_z_and_n_equals_v() {
        let bytes = asm_bytes!(arm, "bgt #0x100");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));
    }

    #[test]
    fn arm_ble_requires_z_or_n_not_equal_v() {
        let bytes = asm_bytes!(arm, "ble #0x100");
        let (mut regs, memory) = arm(bytes, 0x1000);

        regs.cpsr |= 1 << 30;
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1108, false));

        regs.cpsr &= !(1 << 30);
        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1004, false));
    }

    // ARM BX / BLX

    #[test]
    fn arm_bx_register_to_arm() {
        let bytes = asm_bytes!(arm, "bx r0");
        let (mut regs, memory) = arm(bytes, 0x1000);
        regs.r[0] = 0x1234;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1234, false));
    }

    #[test]
    fn arm_bx_register_to_thumb() {
        let bytes = asm_bytes!(arm, "bx r0");
        let (mut regs, memory) = arm(bytes, 0x1000);
        regs.r[0] = 0x1235;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1234, true));
    }

    #[test]
    fn arm_blx_register_to_arm() {
        let bytes = asm_bytes!(arm, "blx r0");
        let (mut regs, memory) = arm(bytes, 0x1000);
        regs.r[0] = 0x1234;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1234, false));
    }

    #[test]
    fn arm_blx_register_to_thumb() {
        let bytes = asm_bytes!(arm, "blx r0");
        let (mut regs, memory) = arm(bytes, 0x1000);
        regs.r[0] = 0x1235;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1234, true));
    }

    #[test]
    fn arm_bx_pc_uses_architectural_pc() {
        let bytes = asm_bytes!(arm, "bx pc");
        let (regs, memory) = arm(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1008, false));
    }

    // Thumb BX / BLX

    #[test]
    fn thumb_bx_register_to_thumb() {
        let bytes = asm_bytes!(thumb, "bx r0");
        let (mut regs, memory) = thumb(bytes, 0x1000);
        regs.r[0] = 0x1235;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1234, true));
    }

    #[test]
    fn thumb_bx_register_to_arm() {
        let bytes = asm_bytes!(thumb, "bx r0");
        let (mut regs, memory) = thumb(bytes, 0x1000);
        regs.r[0] = 0x1234;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1234, false));
    }

    #[test]
    fn thumb_blx_register_to_thumb() {
        let bytes = asm_bytes!(thumb, "blx r0");
        let (mut regs, memory) = thumb(bytes, 0x1000);
        regs.r[0] = 0x1235;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1234, true));
    }

    #[test]
    fn thumb_blx_register_to_arm() {
        let bytes = asm_bytes!(thumb, "blx r0");
        let (mut regs, memory) = thumb(bytes, 0x1000);
        regs.r[0] = 0x1234;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1234, false));
    }

    // Thumb conditional / unconditional branches

    #[test]
    fn thumb_beq_taken() {
        let bytes = asm_bytes!(thumb, "beq #4");
        let (mut regs, memory) = thumb(bytes, 0x1000);

        regs.cpsr |= 1 << 30;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1002, true));
    }

    #[test]
    fn thumb_beq_not_taken() {
        let bytes = asm_bytes!(thumb, "beq #0");
        let (regs, memory) = thumb(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1002, true));
    }

    #[test]
    fn thumb_unconditional_b_zero_offset() {
        let bytes = asm_bytes!(thumb, "b #0");
        let (regs, memory) = thumb(bytes, 0x1000);

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1004, true));
    }

    // ARM PC-writing instructions

    #[test]
    fn arm_mov_pc_register() {
        let bytes = asm_bytes!(arm, "mov pc, r0");
        let (regs, memory) = arm(bytes, 0x1000);

        let mut regs = regs;
        regs.r[0] = 0x1234;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1234, false));
    }

    #[test]
    fn arm_mvn_pc_register() {
        let bytes = asm_bytes!(arm, "mvn pc, r0");
        let (mut regs, memory) = arm(bytes, 0x1000);
        regs.r[0] = 0xfffffff0;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0xc, false));
    }

    #[test]
    fn arm_add_pc_immediate() {
        let bytes = asm_bytes!(arm, "add pc, r0, #4");
        let (mut regs, memory) = arm(bytes, 0x1000);
        regs.r[0] = 0x2000;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x2004, false));
    }

    #[test]
    fn arm_sub_pc_immediate() {
        let bytes = asm_bytes!(arm, "sub pc, r0, #4");
        let (mut regs, memory) = arm(bytes, 0x1000);
        regs.r[0] = 0x2000;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1ffc, false));
    }

    // ARM LDR PC

    #[test]
    fn arm_ldr_pc_register_indirect() {
        let bytes = asm_bytes!(arm, "ldr pc, [r0]");
        let (regs, mut memory) = arm(bytes, 0x1000);

        memory.add(0x2000, &0x1235u32.to_le_bytes());

        let mut regs = regs;
        regs.r[0] = 0x2000;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x1234, true));
    }

    #[test]
    fn arm_ldr_pc_memory_failure_is_reported() {
        let bytes = asm_bytes!(arm, "ldr pc, [r0]");
        let (mut regs, memory) = arm(bytes, 0x1000);

        regs.r[0] = 0x2000;

        assert!(matches!(
            next_pc(&regs, &memory),
            Err(NextPcError::MemoryRead)
        ));
    }

    // ARM LDM

    #[test]
    fn arm_ldm_loads_pc_from_register_list() {
        let bytes = asm_bytes!(arm, "ldmia r0, {r1, pc}");
        let (mut regs, mut memory) = arm(bytes, 0x1000);

        memory.add(0x2004, &[0x67, 0x45, 0x00, 0x00]);
        regs.r[0] = 0x2000;

        assert_eq!(next_pc(&regs, &memory).unwrap(), (0x4566, true));
    }
}
