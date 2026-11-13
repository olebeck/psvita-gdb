use super::{MemReader, RegContext, next_pc};
use asm_rs_macros::asm_bytes;

const ARM_ADDRESS: u32 = 0x1000;

#[derive(Clone, Copy)]
enum MemoryWrite {
    Byte(u32, u8),
    Half(u32, u16),
    Word(u32, u32),
}

struct TestMemory {
    instruction_address: u32,
    instruction: &'static [u8],
    writes: &'static [MemoryWrite],
}

impl MemReader for TestMemory {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Option<()> {
        for (index, output) in buf.iter_mut().enumerate() {
            let address = u32::try_from(addr.checked_add(index)?).ok()?;
            if let Some(offset) = address.checked_sub(self.instruction_address) {
                if let Some(byte) = self.instruction.get(offset as usize) {
                    *output = *byte;
                    continue;
                }
            }

            let mut found = false;
            for write in self.writes {
                let (base, bytes, len): (u32, [u8; 4], usize) = match *write {
                    MemoryWrite::Byte(base, value) => (base, [value, 0, 0, 0], 1),
                    MemoryWrite::Half(base, value) => (base, [value.to_le_bytes()[0], value.to_le_bytes()[1], 0, 0], 2),
                    MemoryWrite::Word(base, value) => (base, value.to_le_bytes(), 4),
                };
                if let Some(offset) = address.checked_sub(base) {
                    if (offset as usize) < len {
                        *output = bytes[offset as usize];
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                return None;
            }
        }
        Some(())
    }
}

struct Case {
    name: &'static str,
    instruction: &'static [u8],
    thumb: bool,
    address: u32,
    registers: &'static [(u8, u32)],
    sp: u32,
    lr: u32,
    flags: u32,
    spsr: u32,
    writes: &'static [MemoryWrite],
    expected: (u32, bool),
}

impl Case {
    fn new(name: &'static str, instruction: &'static [u8], thumb: bool, expected: (u32, bool)) -> Self {
        Self {
            name,
            instruction,
            thumb,
            address: ARM_ADDRESS,
            registers: &[],
            sp: 0,
            lr: 0,
            flags: 0,
            spsr: 0,
            writes: &[],
            expected,
        }
    }

    fn at(mut self, address: u32) -> Self {
        self.address = address;
        self
    }

    fn registers(mut self, registers: &'static [(u8, u32)]) -> Self {
        self.registers = registers;
        self
    }

    fn sp(mut self, sp: u32) -> Self {
        self.sp = sp;
        self
    }

    fn lr(mut self, lr: u32) -> Self {
        self.lr = lr;
        self
    }

    fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    fn spsr(mut self, spsr: u32) -> Self {
        self.spsr = spsr;
        self
    }

    fn writes(mut self, writes: &'static [MemoryWrite]) -> Self {
        self.writes = writes;
        self
    }

    fn run(&self) {
        let mut regs = RegContext {
            pc: self.address.wrapping_add(if self.thumb { 4 } else { 8 }),
            sp: self.sp,
            lr: self.lr,
            cpsr: self.flags | if self.thumb { 1 << 5 } else { 0 },
            spsr: self.spsr,
            ..RegContext::default()
        };
        for &(number, value) in self.registers {
            regs.r[number as usize] = value;
        }

        let memory = TestMemory {
            instruction_address: self.address,
            instruction: self.instruction,
            writes: self.writes,
        };
        let actual = next_pc(&regs, &memory).unwrap_or_else(|error| panic!("{} failed: {error:?}", self.name));
        assert_eq!(actual, self.expected, "{} ({:02x?})", self.name, self.instruction,);
    }
}

macro_rules! arm_case {
    ($name:literal, $instruction:expr, $expected:expr) => {
        Case::new($name, $instruction, false, $expected)
    };
}

macro_rules! thumb_case {
    ($name:literal, $instruction:expr, $expected:expr) => {
        Case::new($name, $instruction, true, $expected)
    };
}

macro_rules! arm_cond_case {
    ($name:literal, $condition:literal, $flags:expr) => {
        Case::new($name, &[0x00, 0x00, 0x00, 0x0a | ($condition << 4)], false, (0x1008, false)).flags($flags)
    };
}

#[test]
fn pc_affecting_instructions_table() {
    use MemoryWrite::{Byte, Half, Word};

    let cases = [
        arm_case!("arm b forward", asm_bytes!(arm, "b #0x20"), (0x1028, false)),
        arm_case!("arm bl forward", asm_bytes!(arm, "bl #0x20"), (0x1028, false)),
        arm_cond_case!("arm cond EQ", 0x0, 1 << 30),
        arm_cond_case!("arm cond NE", 0x1, 0),
        arm_cond_case!("arm cond CS", 0x2, 1 << 29),
        arm_cond_case!("arm cond CC", 0x3, 0),
        arm_cond_case!("arm cond MI", 0x4, 1 << 31),
        arm_cond_case!("arm cond PL", 0x5, 0),
        arm_cond_case!("arm cond VS", 0x6, 1 << 28),
        arm_cond_case!("arm cond VC", 0x7, 0),
        arm_cond_case!("arm cond HI", 0x8, 1 << 29),
        arm_cond_case!("arm cond LS", 0x9, 0),
        arm_cond_case!("arm cond GE", 0xa, 0),
        arm_cond_case!("arm cond LT", 0xb, 1 << 31),
        arm_cond_case!("arm cond GT", 0xc, 0),
        arm_cond_case!("arm cond LE", 0xd, 1 << 30),
        arm_cond_case!("arm cond AL", 0xe, 0),
        arm_case!("arm beq taken", asm_bytes!(arm, "beq #0x20"), (0x1028, false)).flags(1 << 30),
        arm_case!("arm beq not taken", asm_bytes!(arm, "beq #0x20"), (0x1004, false)),
        arm_case!("arm blx immediate H=1", &[0x00, 0x00, 0x00, 0xfb], (0x100a, true)),
        arm_case!("arm bx register arm", asm_bytes!(arm, "bx r0"), (0x1234, false)).registers(&[(0, 0x1234)]),
        arm_case!("arm bx register thumb", asm_bytes!(arm, "bx r0"), (0x1234, true)).registers(&[(0, 0x1235)]),
        arm_case!("arm blx register", asm_bytes!(arm, "blx r0"), (0x1234, true)).registers(&[(0, 0x1235)]),
        thumb_case!("thumb b zero", asm_bytes!(thumb, "b #0"), (0x1002, true)),
        thumb_case!("thumb beq taken", asm_bytes!(thumb, "beq #4"), (0x1004, true)).flags(1 << 30),
        thumb_case!("thumb beq not taken", asm_bytes!(thumb, "beq #4"), (0x1002, true)),
        thumb_case!("thumb bl forward", asm_bytes!(thumb, "bl #8"), (0x1008, true)),
        Case::new("thumb blx immediate to arm", &[0x00, 0xf0, 0x00, 0xeb], true, (0x1604, false)),
        thumb_case!("thumb bx register to thumb", asm_bytes!(thumb, "bx r0"), (0x1234, true)).registers(&[(0, 0x1235)]),
        thumb_case!("thumb blx register to arm", asm_bytes!(thumb, "blx r0"), (0x1234, false))
            .registers(&[(0, 0x1234)]),
        thumb_case!("thumb cbz taken", &[0x10, 0xb1], (0x1008, true)).registers(&[(0, 0)]),
        thumb_case!("thumb cbz not taken", &[0x10, 0xb1], (0x1002, true)).registers(&[(0, 1)]),
        thumb_case!("thumb cbnz taken", &[0x10, 0xb9], (0x1008, true)).registers(&[(0, 1)]),
        thumb_case!("thumb cbnz not taken", &[0x10, 0xb9], (0x1002, true)).registers(&[(0, 0)]),
        arm_case!("arm mov pc, register", asm_bytes!(arm, "mov pc, r0"), (0x1234, false)).registers(&[(0, 0x1234)]),
        arm_case!(
            "arm mov pc, shifted register",
            asm_bytes!(arm, "mov pc, r0, lsl #2"),
            (0x48d0, false)
        )
        .registers(&[(0, 0x1234)]),
        arm_case!("arm add pc", asm_bytes!(arm, "add pc, r0, #4"), (0x2004, false)).registers(&[(0, 0x2000)]),
        arm_case!("arm sub pc", asm_bytes!(arm, "sub pc, r0, #4"), (0x1ffc, false)).registers(&[(0, 0x2000)]),
        arm_case!("arm rsb pc", asm_bytes!(arm, "rsb pc, r0, #0x2000"), (0x1000, false)).registers(&[(0, 0x1000)]),
        arm_case!("arm and pc", asm_bytes!(arm, "and pc, r0, r1"), (0x1200, false))
            .registers(&[(0, 0x12ff), (1, 0x1200)]),
        arm_case!("arm eor pc", asm_bytes!(arm, "eor pc, r0, r1"), (0x30, false)).registers(&[(0, 0x10), (1, 0x20)]),
        arm_case!("arm orr pc", asm_bytes!(arm, "orr pc, r0, r1"), (0x30, false)).registers(&[(0, 0x10), (1, 0x20)]),
        arm_case!("arm bic pc", asm_bytes!(arm, "bic pc, r0, r1"), (0x10, false)).registers(&[(0, 0x1f), (1, 0x0f)]),
        arm_case!("arm mvn pc interworks", asm_bytes!(arm, "mvn pc, r0"), (0xe, true)).registers(&[(0, 0xfffffff0)]),
        arm_case!("arm adc pc with carry", asm_bytes!(arm, "adc pc, r0, r1"), (0x30, true))
            .registers(&[(0, 0x10), (1, 0x20)])
            .flags(1 << 29),
        arm_case!("arm sbc pc with carry", asm_bytes!(arm, "sbc pc, r0, r1"), (0x10, false))
            .registers(&[(0, 0x30), (1, 0x20)])
            .flags(1 << 29),
        arm_case!("arm rsc pc with carry", asm_bytes!(arm, "rsc pc, r0, r1"), (0x10, false))
            .registers(&[(0, 0x20), (1, 0x30)])
            .flags(1 << 29),
        thumb_case!("thumb add pc, low register", asm_bytes!(thumb, "add pc, r0"), (0x1236, true))
            .registers(&[(0, 0x1236)]),
        thumb_case!("thumb mov pc preserves bit 1", asm_bytes!(thumb, "mov pc, r0"), (0x1236, true))
            .at(0x1002)
            .registers(&[(0, 0x1236)]),
        arm_case!("arm adr add", asm_bytes!(arm, "add pc, pc, #4"), (0x100c, false)),
        arm_case!("arm adr subtract", asm_bytes!(arm, "sub pc, pc, #4"), (0x1004, false)),
        Case::new("thumb ldr literal aligned pc", &[0xdf, 0xf8, 0x04, 0xf0], true, (0x2000, true))
            .at(0x1002)
            .writes(&[Word(0x1008, 0x2001)]),
        arm_case!("arm ldr register indirect", asm_bytes!(arm, "ldr pc, [r0]"), (0x1234, true))
            .registers(&[(0, 0x2000)])
            .writes(&[Word(0x2000, 0x1235)]),
        arm_case!(
            "arm ldr immediate preindex add",
            asm_bytes!(arm, "ldr pc, [r0, #4]"),
            (0x1234, true)
        )
        .registers(&[(0, 0x2000)])
        .writes(&[Word(0x2004, 0x1235)]),
        arm_case!(
            "arm ldr immediate preindex subtract",
            asm_bytes!(arm, "ldr pc, [r0, #-4]"),
            (0x1234, true)
        )
        .registers(&[(0, 0x2000)])
        .writes(&[Word(0x1ffc, 0x1235)]),
        arm_case!("arm ldr register offset", asm_bytes!(arm, "ldr pc, [r0, r1]"), (0x1234, true))
            .registers(&[(0, 0x2000), (1, 4)])
            .writes(&[Word(0x2004, 0x1235)]),
        arm_case!("arm ldr shifted register offset", &[0x01, 0xf1, 0x90, 0xe7], (0x1234, false))
            .registers(&[(0, 0x2000), (1, 1)])
            .writes(&[Word(0x2004, 0x1234)]),
        arm_case!("arm ldr postindex", asm_bytes!(arm, "ldr pc, [r0], #4"), (0x1234, false))
            .registers(&[(0, 0x2000)])
            .writes(&[Word(0x2000, 0x1234)]),
        arm_case!("arm ldmia pc", asm_bytes!(arm, "ldmia r0, {r1, pc}"), (0x4566, true))
            .registers(&[(0, 0x2000)])
            .writes(&[Word(0x2004, 0x4567)]),
        arm_case!("arm ldmib pc", asm_bytes!(arm, "ldmib r0, {r1, pc}"), (0x4566, true))
            .registers(&[(0, 0x2000)])
            .writes(&[Word(0x2008, 0x4567)]),
        arm_case!("arm ldmda pc", asm_bytes!(arm, "ldmda r0, {r1, pc}"), (0x4566, true))
            .registers(&[(0, 0x2008)])
            .writes(&[Word(0x2008, 0x4567)]),
        arm_case!("arm ldmdb pc", asm_bytes!(arm, "ldmdb r0, {r1, pc}"), (0x4566, true))
            .registers(&[(0, 0x2008)])
            .writes(&[Word(0x2004, 0x4567)]),
        thumb_case!("thumb pop pc", asm_bytes!(thumb, "pop {pc}"), (0x4566, true))
            .sp(0x3000)
            .writes(&[Word(0x3000, 0x4567)]),
        Case::new("thumb tbb register index", &[0xd0, 0xe8, 0x01, 0xf0], true, (0x100a, true))
            .registers(&[(0, 0x2000), (1, 3)])
            .writes(&[Byte(0x2003, 3)]),
        Case::new(
            "thumb tbh scaled register index",
            &[0xd0, 0xe8, 0x11, 0xf0],
            true,
            (0x100a, true),
        )
        .registers(&[(0, 0x2000), (1, 3)])
        .writes(&[Half(0x2006, 3)]),
        arm_case!(
            "arm movs pc restores thumb state",
            asm_bytes!(arm, "movs pc, lr"),
            (0x1236, true)
        )
        .lr(0x1237)
        .spsr(1 << 5),
        arm_case!(
            "arm movs pc restores arm state",
            asm_bytes!(arm, "movs pc, lr"),
            (0x1234, false)
        )
        .lr(0x1237)
        .spsr(0),
        Case::new("arm ldm exception return", &[0x00, 0x80, 0xd0, 0xe8], false, (0x4566, true))
            .registers(&[(0, 0x2000)])
            .spsr(1 << 5)
            .writes(&[Word(0x2000, 0x4567)]),
        Case::new(
            "arm rfe ia restores thumb state",
            &[0x00, 0x0a, 0xb0, 0xf8],
            false,
            (0x1236, true),
        )
        .registers(&[(0, 0x2000)])
        .writes(&[Word(0x2000, 0x1237), Word(0x2004, 1 << 5)]),
        Case::new(
            "arm rfe db restores arm state",
            &[0x00, 0x0a, 0x30, 0xf9],
            false,
            (0x1234, false),
        )
        .registers(&[(0, 0x2008)])
        .writes(&[Word(0x2000, 0x1237), Word(0x2004, 0)]),
    ];

    for case in cases {
        case.run();
    }
}
