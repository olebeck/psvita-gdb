use core::{mem::zeroed, num::NonZero};

use arm_next_pc::{MemReader, RegContext};
use gdbstub::{
    common::{Signal, Tid},
    target::{
        TargetError, TargetResult,
        ext::{
            base::{
                multithread::{
                    MultiThreadBase, MultiThreadResume, MultiThreadResumeOps,
                    MultiThreadSchedulerLocking, MultiThreadSchedulerLockingOps,
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
            ksceKernelCopyFromUserProc, ksceKernelResumeProcess, ksceKernelSetThreadCpuRegisters,
            ksceKernelSetVfpRegisterForDebugger,
        },
        utils::{
            PROCESS_STATUS_SUSPENDED, SceError, get_process_status, get_thread_ids,
            get_thread_info, name_to_str, write_user_text,
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
        if self.session.is_none() {
            return Err(gdbstub::target::TargetError::NonFatal);
        }
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
            data.fill(0);
            return Ok(data.len());
        };

        if let Err(err) = sce_call!(ksceKernelCopyFromUserProc(
            pid,
            data.as_mut_ptr() as _,
            start_addr as _,
            data.len() as _
        )) {
            println!("read_addrs {err} addr=0x{start_addr:x}");
            return Err(TargetError::NonFatal);
        }
        Ok(data.len())
    }

    fn write_addrs(&mut self, start_addr: u32, data: &[u8], _tid: Tid) -> TargetResult<(), Self> {
        let Some(pid) = self.pid() else {
            return Ok(());
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
            thread_is_active(Tid::new(tid as usize).unwrap());
        }
        Ok(())
    }

    #[inline(always)]
    fn is_thread_alive(&mut self, tid: Tid) -> Result<bool, Self::Error> {
        Ok(get_thread_info(tid.get() as SceUID).is_ok())
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
    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, Tid, Self>> {
        Some(self)
    }
}

impl MemReader for VitaTarget {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Option<()> {
        let pid = self.pid().unwrap();
        if let Err(err) = sce_call!(ksceKernelCopyFromUserProc(
            pid,
            buf.as_mut_ptr() as _,
            addr as _,
            buf.len() as _
        )) {
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
        for tid in self.continue_actions.as_ref() {
            println!("continue {}", *tid)
        }
        println!("scheduler_lock {}", self.scheduler_lock);

        const STATUS_SUSPEND: i32 = 1;
        const STATUS_RUNNING: i32 = 2;

        for tid in get_thread_ids(pid)? {
            let mut status = STATUS_RUNNING;

            if self.scheduler_lock {
                status = STATUS_SUSPEND;
            }

            if self.step_action.is_some_and(|id| id == tid) {
                self.step_action = None;
                status = STATUS_RUNNING;

                let thid = NonZero::new(tid as usize).unwrap();
                let mut regs = Armv7Regs::default();
                self.read_registers(&mut regs, thid)
                    .map_err(|_err| SceError::new(-1, "read_registers"))?;

                let mut insn = [0u8; 4];
                self.read(regs.pc as _, &mut insn).unwrap();

                let thumb = (regs.cpsr >> 5) & 1 != 0;
                println!("insn: {:02x?} thumb {}", insn, thumb);

                regs.pc = regs.pc.wrapping_add(if thumb { 4 } else { 8 });
                match arm_next_pc::next_pc(&arm_reg_context(&regs), self) {
                    Err(err) => {
                        println!("next_pc: {err:?}");
                        return Err(SceError::new(-1, "next_pc"));
                    }
                    Ok((addr, thumb)) => {
                        println!("curr_pc={:x} next_pc={:x}", regs.pc, addr);

                        let session = self.session.as_ref().unwrap();
                        let kind = if thumb {
                            ArmBreakpointKind::Thumb16
                        } else {
                            ArmBreakpointKind::Arm32
                        };
                        session.inner().set_sw_breakpoint(addr, kind);
                        session.set_step(tid, addr)?;
                    }
                }
            }

            if self
                .continue_actions
                .iter()
                .find(|id| **id == tid)
                .is_some()
            {
                status = STATUS_RUNNING;
            }

            println!("ksceKernelChangeThreadSuspendStatus({tid}, {status})");
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
        self.scheduler_lock = false;
        Ok(())
    }

    fn set_resume_action_continue(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        if signal.is_some() {
            return Err(SceError::new(-1, "set_resume_action_continue"));
        }
        let tid = tid.get() as SceUID;
        if let Err(_) = self.continue_actions.try_push(tid) {
            return Err(SceError::new(-1, "continue_actions full"));
        }
        Ok(())
    }

    fn support_single_step(&mut self) -> Option<MultiThreadSingleStepOps<'_, Self>> {
        Some(self)
    }

    fn support_scheduler_locking(&mut self) -> Option<MultiThreadSchedulerLockingOps<'_, Self>> {
        Some(self)
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

impl MultiThreadSchedulerLocking for VitaTarget {
    fn set_resume_action_scheduler_lock(&mut self) -> Result<(), Self::Error> {
        self.scheduler_lock = true;
        Ok(())
    }
}

impl ThreadExtraInfo for VitaTarget {
    fn thread_extra_info(&self, tid: Tid, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if self.session.is_none() {
            return Ok(0);
        }
        let info = get_thread_info(tid.get() as SceUID)?;
        let name = name_to_str(info.name.as_slice());
        let len = name.len().min(buf.len());
        buf[..len].copy_from_slice(&name.as_bytes()[..len]);
        Ok(len)
    }
}

impl SingleRegisterAccess<Tid> for VitaTarget {
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
            buf.copy_from_slice(&vfp[dpr as usize].to_le_bytes());
            return Ok(buf.len());
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
                _ => unreachable!(),
            },
            Armv7RegId::Sp => th_regs.sp,
            Armv7RegId::Lr => th_regs.lr,
            Armv7RegId::Pc => th_regs.pc,
            Armv7RegId::Cpsr => th_regs.cpsr,
            Armv7RegId::Fpscr => th_regs.fpscr,
            _ => todo!("neon"),
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
        let value = u32::from_le_bytes(val.try_into().unwrap());

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
                _ => unreachable!(),
            },
            Armv7RegId::Sp => (&mut regs.sp, SCE_REG_SP),
            Armv7RegId::Lr => (&mut regs.lr, SCE_REG_LR),
            Armv7RegId::Pc => (&mut regs.pc, SCE_REG_PC),
            Armv7RegId::Cpsr => (&mut regs.cpsr, SCE_REG_CPSR),
            Armv7RegId::Fpscr => (&mut regs.fpscr, SCE_REG_FPSCR),
            _ => return Err(TargetError::NonFatal),
        };
        *reg = value;

        if let Err(err) = sce_call!(ksceKernelSetThreadCpuRegisters(tid, &regs, mask)) {
            println!("write_register {err} tid={tid}");
            return Err(TargetError::NonFatal);
        }
        Ok(())
    }
}
