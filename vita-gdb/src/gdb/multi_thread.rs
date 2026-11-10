use core::mem::zeroed;

use arm_next_pc::{MemReader, RegContext};
use gdbstub::{
    common::{Signal, Tid},
    target::{
        TargetError, TargetResult,
        ext::{
            base::{
                multithread::{
                    MultiThreadBase, MultiThreadResume, MultiThreadResumeOps,
                    MultiThreadSingleStep, MultiThreadSingleStepOps,
                },
                single_register_access::{SingleRegisterAccess, SingleRegisterAccessOps},
            },
            thread_extra_info::{ThreadExtraInfo, ThreadExtraInfoOps},
        },
    },
};
use gdbstub_arch::arm::ArmBreakpointKind;
use vitasdk_sys::{
    SceArmCpuRegisters, SceThreadCpuRegisters, SceUID, ksceKernelChangeThreadSuspendStatus,
    ksceKernelGetThreadCpuRegisters, ksceKernelGetVfpRegisterForDebugger,
};

use crate::{
    gdb::{
        armv7::{Armv7RegId, Armv7Regs},
        target::VitaTarget,
    },
    kernel::{
        ffi::{
            ksceKernelResumeProcess, ksceKernelSetThreadCpuRegisters,
            ksceKernelSetVfpRegisterForDebugger,
        },
        utils::{
            PROCESS_STATUS_SUSPENDED, SceError, get_process_status, get_thread_ids,
            get_thread_info, name_to_str, read_user_process, str_to_buf, write_user_text,
        },
    },
    println, sce_call,
};

pub const SCE_REG_R0: u32 = 1 << 0;
pub const SCE_REG_R1: u32 = 1 << 1;
pub const SCE_REG_R2: u32 = 1 << 2;
pub const SCE_REG_R3: u32 = 1 << 3;
pub const SCE_REG_R4: u32 = 1 << 4;
pub const SCE_REG_R5: u32 = 1 << 5;
pub const SCE_REG_R6: u32 = 1 << 6;
pub const SCE_REG_R7: u32 = 1 << 7;
pub const SCE_REG_R8: u32 = 1 << 8;
pub const SCE_REG_R9: u32 = 1 << 9;
pub const SCE_REG_R10: u32 = 1 << 10;
pub const SCE_REG_R11: u32 = 1 << 11;
pub const SCE_REG_R12: u32 = 1 << 12;
pub const SCE_REG_SP: u32 = 1 << 13;
pub const SCE_REG_LR: u32 = 1 << 14;
pub const SCE_REG_PC: u32 = 1 << 15;
pub const SCE_REG_CPSR: u32 = 1 << 16;
pub const SCE_REG_FPSCR: u32 = 1 << 17;

impl MultiThreadBase for VitaTarget {
    fn read_registers(&mut self, regs: &mut Armv7Regs, tid: Tid) -> TargetResult<(), Self> {
        let tid = tid.get() as SceUID;

        let mut registers: SceThreadCpuRegisters = unsafe { zeroed() };
        if let Err(err) = sce_call!(ksceKernelGetThreadCpuRegisters(tid, &mut registers)) {
            println!("read_registers {err} tid={tid}");
            return Err(TargetError::NonFatal);
        }

        let entries = unsafe { &registers.__bindgen_anon_1.entry };
        let th_regs = if entries[0].cpsr & 0x1F == 0x10 {
            &entries[0]
        } else {
            &entries[1]
        };

        regs.r[0] = th_regs.r0;
        regs.r[1] = th_regs.r1;
        regs.r[2] = th_regs.r2;
        regs.r[3] = th_regs.r3;
        regs.r[4] = th_regs.r4;
        regs.r[5] = th_regs.r5;
        regs.r[6] = th_regs.r6;
        regs.r[7] = th_regs.r7;
        regs.r[8] = th_regs.r8;
        regs.r[9] = th_regs.r9;
        regs.r[10] = th_regs.r10;
        regs.r[11] = th_regs.r11;
        regs.r[12] = th_regs.r12;
        regs.sp = th_regs.sp;
        regs.lr = th_regs.lr;
        regs.pc = th_regs.pc;
        regs.cpsr = th_regs.cpsr;
        //TODO regs.spsr = th_regs.spsr;
        regs.fpscr = th_regs.fpscr;

        regs.d = [0x7ff8dead7f80deadu64; 32];
        match sce_call!(ksceKernelGetVfpRegisterForDebugger(
            tid,
            &raw mut regs.d as _
        )) {
            Ok(_) => (),
            Err(err) if err.code == 0x80020008u32 as i32 => (),
            Err(err) => {
                println!("read_register {err} tid={tid}");
                return Err(gdbstub::target::TargetError::NonFatal);
            }
        };

        Ok(())
    }

    fn write_registers(&mut self, regs: &Armv7Regs, tid: Tid) -> TargetResult<(), Self> {
        let tid = tid.get() as SceUID;

        let sce_regs = SceArmCpuRegisters {
            r0: regs.r[0],
            r1: regs.r[1],
            r2: regs.r[2],
            r3: regs.r[3],
            r4: regs.r[4],
            r5: regs.r[5],
            r6: regs.r[6],
            r7: regs.r[7],
            r8: regs.r[8],
            r9: regs.r[9],
            r10: regs.r[10],
            r11: regs.r[11],
            r12: regs.r[12],
            sp: regs.sp,
            lr: regs.lr,
            pc: regs.pc,
            cpsr: regs.cpsr,
            fpscr: regs.fpscr,
        };
        let mask = SCE_REG_R0
            | SCE_REG_R1
            | SCE_REG_R2
            | SCE_REG_R3
            | SCE_REG_R4
            | SCE_REG_R5
            | SCE_REG_R6
            | SCE_REG_R7
            | SCE_REG_R8
            | SCE_REG_R9
            | SCE_REG_R10
            | SCE_REG_R11
            | SCE_REG_R12
            | SCE_REG_SP
            | SCE_REG_LR
            | SCE_REG_PC
            | SCE_REG_CPSR
            | SCE_REG_FPSCR;
        if let Err(err) = sce_call!(ksceKernelSetThreadCpuRegisters(tid, &sce_regs, mask)) {
            println!("write_registers {err} tid={tid}");
            return Err(TargetError::NonFatal);
        }

        if let Err(err) = sce_call!(ksceKernelSetVfpRegisterForDebugger(
            tid,
            &regs.d as *const _ as _
        )) {
            println!("write_registers {err} tid={tid}");
            return Err(TargetError::NonFatal);
        }

        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: u32,
        data: &mut [u8],
        _tid: Tid,
    ) -> TargetResult<usize, Self> {
        let Some(pid) = self.pid() else {
            return Err(TargetError::NonFatal);
        };
        if let Err(err) = read_user_process(pid, start_addr, data) {
            println!("read_addrs {err} addr=0x{start_addr:x}");
            return Err(TargetError::NonFatal);
        }
        Ok(data.len())
    }

    fn write_addrs(&mut self, start_addr: u32, data: &[u8], _tid: Tid) -> TargetResult<(), Self> {
        let Some(pid) = self.pid() else {
            return Err(TargetError::NonFatal);
        };
        if let Err(err) = write_user_text(pid, start_addr, data) {
            println!("write_addrs {err} addr=0x{start_addr:x}");
            return Err(TargetError::NonFatal);
        }
        Ok(())
    }

    #[inline(always)]
    fn list_active_threads(
        &mut self,
        thread_is_active: &mut dyn FnMut(Tid),
    ) -> Result<(), Self::Error> {
        let Some(pid) = self.pid() else {
            return Ok(());
        };
        for tid in get_thread_ids(pid)? {
            let thid = unsafe { Tid::new_unchecked(tid as _) };
            thread_is_active(thid);
        }
        Ok(())
    }

    #[inline(always)]
    fn is_thread_alive(&mut self, tid: Tid) -> Result<bool, Self::Error> {
        let tid = tid.get() as SceUID;
        Ok(get_thread_info(tid).is_ok())
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<MultiThreadResumeOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_thread_extra_info(&mut self) -> Option<ThreadExtraInfoOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, Self>> {
        Some(self)
    }
}

impl MemReader for VitaTarget {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Option<()> {
        let pid = self.pid()?;
        if let Err(err) = read_user_process(pid, addr as _, buf) {
            println!("read_addrs {err} addr=0x{addr:x}");
            return None;
        }
        Some(())
    }
}

fn arm_reg_context(regs: &Armv7Regs) -> RegContext {
    RegContext {
        r: regs.r,
        sp: regs.sp,
        lr: regs.lr,
        pc: regs.pc,
        cpsr: regs.cpsr,
        spsr: regs.spsr,
    }
}

impl MultiThreadResume for VitaTarget {
    fn resume(&mut self) -> Result<(), Self::Error> {
        let Some(pid) = self.pid() else {
            return Ok(());
        };

        let status = get_process_status(pid)?;
        if status & PROCESS_STATUS_SUSPENDED == 0 {
            return Ok(());
        }

        if let Some(session) = self.session.as_ref() {
            if session.inner().has_excp() && self.step_action.is_none() {
                return Ok(()); // not actually resuming to pop pending exception
            }
        }

        if let Some(step) = self.step_action {
            println!("stepping {step}");
        }
        for tid in self.continue_actions.iter() {
            println!("continue {}", tid)
        }

        const STATUS_SUSPEND: i32 = 1;
        const STATUS_RUNNING: i32 = 2;

        for tid in get_thread_ids(pid)? {
            let mut status = STATUS_RUNNING;

            if !self.continue_actions.is_empty() {
                status = STATUS_SUSPEND;
            }

            if self.step_action.is_some_and(|id| id == tid) {
                self.step_action = None;
                status = STATUS_RUNNING;
                self.set_step(tid)?;
            }

            if self.continue_actions.contains(&tid) {
                status = STATUS_RUNNING;
            }

            if let Err(err) = sce_call!(ksceKernelChangeThreadSuspendStatus(tid, status)) {
                println!("{err} tid={tid}");
            }
        }
        sce_call!(ksceKernelResumeProcess(pid))?;
        Ok(())
    }

    fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
        self.step_action = None;
        self.continue_actions.clear();
        Ok(())
    }

    fn set_resume_action_continue(
        &mut self,
        tid: Option<Tid>,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        if signal.is_some() {
            return Err(SceError::new(-1, "set_resume_action_continue"));
        }
        if let Some(tid) = tid {
            let tid = tid.get() as SceUID;
            if self.continue_actions.push(tid).is_err() {
                return Err(SceError::new(-1, "continue_actions full"));
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn support_single_step(&mut self) -> Option<MultiThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl VitaTarget {
    fn set_step(&mut self, tid: SceUID) -> Result<(), SceError> {
        let thid = unsafe { Tid::new_unchecked(tid as _) };

        let mut regs = Armv7Regs::default();
        if let Err(_err) = self.read_registers(&mut regs, thid) {
            return Err(SceError::new(-1, "read_registers"));
        }

        let insn_addr = regs.pc as usize;
        let mut insn = [0u8; 4];
        if self.read(insn_addr, &mut insn).is_none() {
            return Err(SceError::new(-1, "read_registers read pc insn"));
        }

        let thumb = (regs.cpsr >> 5) & 1 != 0;
        println!("insn: {:02x?} thumb {}", insn, thumb);

        regs.pc = regs.pc.wrapping_add(if thumb { 4 } else { 8 });
        let (addr, thumb) = match arm_next_pc::next_pc(&arm_reg_context(&regs), self) {
            Err(err) => {
                println!("next_pc: {err:?}");
                return Err(SceError::new(-1, "next_pc"));
            }
            Ok(next) => next,
        };
        println!("curr_pc={:x} next_pc={:x}", insn_addr, addr);

        let kind = if thumb {
            ArmBreakpointKind::Thumb16
        } else {
            ArmBreakpointKind::Arm32
        };

        let Some(session) = self.session.as_ref() else {
            return Ok(());
        };
        session.set_step(tid, addr, kind)
    }
}

impl MultiThreadSingleStep for VitaTarget {
    fn set_resume_action_step(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        if signal.is_some() {
            return Err(SceError::new(-1, "set_resume_action_step"));
        }
        let tid = tid.get() as SceUID;
        self.step_action = Some(tid);
        Ok(())
    }
}

impl ThreadExtraInfo for VitaTarget {
    fn thread_extra_info(&self, tid: Tid, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if self.session.is_none() {
            return Ok(0);
        }
        let info = get_thread_info(tid.get() as SceUID)?;
        let Some(name) = name_to_str(&info.name) else {
            return Ok(0);
        };
        Ok(str_to_buf(buf, name, 0))
    }
}

impl SingleRegisterAccess for VitaTarget {
    fn read_register(
        &mut self,
        tid: Tid,
        reg_id: Armv7RegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        if self.session.is_none() {
            return Ok(0);
        }
        let tid = tid.get() as SceUID;

        if let Armv7RegId::Dpr(dpr) = reg_id {
            let mut vfp = [0x7ff8dead7f80deadu64; 32];
            match sce_call!(ksceKernelGetVfpRegisterForDebugger(tid, &raw mut vfp as _)) {
                Ok(_) => (),
                Err(err) if err.code == 0x80020008u32 as i32 => (),
                Err(err) => {
                    println!("read_register {err} tid={tid}");
                    return Err(gdbstub::target::TargetError::NonFatal);
                }
            };
            let Some(reg) = vfp.get(dpr as usize) else {
                return Ok(0);
            };
            for (dst, val) in buf.iter_mut().zip(&reg.to_le_bytes()) {
                *dst = *val;
            }
            return Ok(8);
        };

        let mut registers: SceThreadCpuRegisters = unsafe { zeroed() };
        if let Err(err) = sce_call!(ksceKernelGetThreadCpuRegisters(tid, &mut registers)) {
            println!("read_register {err} tid={tid}");
            return Err(gdbstub::target::TargetError::NonFatal);
        }

        let entries = unsafe { &registers.__bindgen_anon_1.entry };
        let th_regs = if entries[0].cpsr & 0x1F == 0x10 {
            &entries[0]
        } else {
            &entries[1]
        };

        let value = match reg_id {
            Armv7RegId::Gpr(n) => match n {
                0 => th_regs.r0,
                1 => th_regs.r1,
                2 => th_regs.r2,
                3 => th_regs.r3,
                4 => th_regs.r4,
                5 => th_regs.r5,
                6 => th_regs.r6,
                7 => th_regs.r7,
                8 => th_regs.r8,
                9 => th_regs.r9,
                10 => th_regs.r10,
                11 => th_regs.r11,
                12 => th_regs.r12,
                _ => 0xdeadbeef,
            },
            Armv7RegId::Sp => th_regs.sp,
            Armv7RegId::Lr => th_regs.lr,
            Armv7RegId::Pc => th_regs.pc,
            Armv7RegId::Cpsr => th_regs.cpsr,
            Armv7RegId::Dpr(_) => 0xdeadbeef, // TODO
            Armv7RegId::Fpscr => th_regs.fpscr,
        };
        buf.copy_from_slice(&value.to_le_bytes());
        Ok(buf.len())
    }

    fn write_register(
        &mut self,
        tid: Tid,
        reg_id: Armv7RegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        let tid = tid.get() as SceUID;
        let Ok(value) = val.try_into().map(u32::from_le_bytes) else {
            return Ok(());
        };

        let mut regs: SceArmCpuRegisters = unsafe { zeroed() };
        let (reg, mask) = match reg_id {
            Armv7RegId::Gpr(n) => match n {
                0 => (&mut regs.r0, SCE_REG_R0),
                1 => (&mut regs.r1, SCE_REG_R1),
                2 => (&mut regs.r2, SCE_REG_R2),
                3 => (&mut regs.r3, SCE_REG_R3),
                4 => (&mut regs.r4, SCE_REG_R4),
                5 => (&mut regs.r5, SCE_REG_R5),
                6 => (&mut regs.r6, SCE_REG_R6),
                7 => (&mut regs.r7, SCE_REG_R7),
                8 => (&mut regs.r8, SCE_REG_R8),
                9 => (&mut regs.r9, SCE_REG_R9),
                10 => (&mut regs.r10, SCE_REG_R10),
                11 => (&mut regs.r11, SCE_REG_R11),
                12 => (&mut regs.r12, SCE_REG_R12),
                _ => return Err(TargetError::NonFatal),
            },
            Armv7RegId::Sp => (&mut regs.sp, SCE_REG_SP),
            Armv7RegId::Lr => (&mut regs.lr, SCE_REG_LR),
            Armv7RegId::Pc => (&mut regs.pc, SCE_REG_PC),
            Armv7RegId::Cpsr => (&mut regs.cpsr, SCE_REG_CPSR),
            Armv7RegId::Dpr(_) => return Err(TargetError::NonFatal),
            Armv7RegId::Fpscr => (&mut regs.fpscr, SCE_REG_FPSCR),
        };
        *reg = value;

        if let Err(err) = sce_call!(ksceKernelSetThreadCpuRegisters(tid, &regs, mask)) {
            println!("write_register {err} tid={tid}");
            return Err(TargetError::NonFatal);
        }
        Ok(())
    }
}
