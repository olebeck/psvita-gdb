use core::{
    cell::UnsafeCell,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
};

use gdbstub_arch::arm::ArmBreakpointKind;
use vitasdk_sys::SceUID;

use gdbstub::target::ext::breakpoints::WatchKind;

use crate::kernel::{
    event_flag::EventFlagRef,
    ffi::{stai_is_loaded, staiCowRelease, staiCowWrite},
    mpsc::MpscRing,
    spinlock::Spinlock,
    utils::read_user_process,
};
use crate::{
    cp14::is_debug_enabled,
    kernel::{
        ffi::{ksceKernelSetPHBP, ksceKernelSetPHWP, ksceKernelSetTHBP},
        utils::{SceError, write_user_text},
    },
};
use crate::{println, sce_call};

const MAX_SESSIONS: usize = 4;
const PID_UNUSED: i32 = -1;

pub const EV_WAKE_WORKER: u32 = 1 << 0;
pub const EV_WAKE_READER: u32 = 1 << 1;

static SESSION_POOL: [GdbSessionInner; MAX_SESSIONS] =
    [const { GdbSessionInner::uninit() }; MAX_SESSIONS];
static SESSION_ALLOC_LOCK: Spinlock<()> = Spinlock::new(());

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ExceptionKind {
    Dabt,
    Pabt,
    Undef,
}

#[derive(Copy, Clone, Debug)]
pub enum ExceptionEvent {
    HwBreak {
        tid: SceUID,
    },
    SwBreak {
        tid: SceUID,
    },
    Watch {
        tid: SceUID,
        addr: u32,
        kind: WatchKind,
    },
    Exception {
        tid: SceUID,
        kind: ExceptionKind,
    },
}

#[derive(Clone)]
pub struct HwWatchpoint {
    addr: u32,
    kind: WatchKind,
}

#[derive(Clone)]
pub struct HwBreakpoint {
    addr: u32,
}

#[derive(Debug, Clone)]
pub enum SwBreakpoint {
    Claimed {
        addr: u32,
    },
    Patched {
        addr: u32,
        orig: [u8; 4],
        len: usize,
    },
    Shared {
        addr: u32,
        uid: SceUID,
    },
}
impl SwBreakpoint {
    pub fn addr(&self) -> u32 {
        match *self {
            Self::Claimed { addr } | Self::Patched { addr, .. } | Self::Shared { addr, .. } => addr,
        }
    }
}

#[derive(Debug, Clone)]
pub enum StepBreakpoint {
    Hw { tid: SceUID, addr: u32 },
    Sw { tid: SceUID, bp: SwBreakpoint },
}

impl StepBreakpoint {
    pub fn tid(&self) -> SceUID {
        match *self {
            Self::Hw { tid, .. } | Self::Sw { tid, .. } => tid,
        }
    }

    pub fn addr(&self) -> u32 {
        match self {
            Self::Hw { addr, .. } => *addr,
            Self::Sw { bp, .. } => bp.addr(),
        }
    }
}

pub struct GdbSessionInner {
    pid: AtomicI32,
    evflag: UnsafeCell<Option<EventFlagRef>>,

    hw_breakpoints: Spinlock<[Option<HwBreakpoint>; 5]>,
    hw_watchpoints: Spinlock<[Option<HwWatchpoint>; 3]>,
    sw_breakpoints: Spinlock<[Option<SwBreakpoint>; 16]>,
    step: Spinlock<Option<StepBreakpoint>>,
    step_result: Spinlock<Option<SceUID>>,
    exited: AtomicBool,
    exceptions: MpscRing<ExceptionEvent, 8>,
}

unsafe impl Sync for GdbSessionInner {}

impl GdbSessionInner {
    const fn uninit() -> Self {
        Self {
            pid: AtomicI32::new(PID_UNUSED),
            evflag: UnsafeCell::new(None),

            hw_breakpoints: Spinlock::new([const { None }; 5]),
            hw_watchpoints: Spinlock::new([const { None }; 3]),
            sw_breakpoints: Spinlock::new([const { None }; 16]),
            step: Spinlock::new(None),
            step_result: Spinlock::new(None),
            exited: AtomicBool::new(false),
            exceptions: MpscRing::new(),
        }
    }

    pub fn reset(&self) {
        if let Some(evflag) = self.evflag() {
            let _ = evflag.clear(EV_WAKE_WORKER);
            unsafe { *self.evflag.get() = None }
        }
        self.hw_breakpoints.lock().fill(None);
        self.hw_watchpoints.lock().fill(None);
        self.sw_breakpoints.lock().fill(None);
        *self.step.lock() = None;
        *self.step_result.lock() = None;
        self.exited.store(false, Ordering::Release);
        self.exceptions.clear();
        self.pid.store(PID_UNUSED, Ordering::Release);
    }

    pub fn pid(&self) -> SceUID {
        match self.pid.load(Ordering::Acquire) {
            PID_UNUSED => -1,
            pid => pid,
        }
    }

    pub fn push_excp(&self, event: ExceptionEvent) {
        let Some(evflag) = self.evflag() else {
            return;
        };
        if !self.exceptions.push(event) {
            println!("exceptions overflow");
        }
        let _ = evflag.set(EV_WAKE_WORKER);
    }

    pub fn pop_excp(&self) -> Option<ExceptionEvent> {
        self.exceptions.pop()
    }

    pub fn has_excp(&self) -> bool {
        self.exceptions.len() > 0
    }

    pub fn push_exited(&self) {
        let Some(evflag) = self.evflag() else {
            return;
        };
        self.exited.store(true, Ordering::Release);
        let _ = evflag.set(EV_WAKE_WORKER);
    }

    pub fn pop_exited(&self) -> bool {
        self.exited.swap(false, Ordering::Release)
    }

    pub fn set_step(
        &self,
        tid: SceUID,
        addr: u32,
        kind: ArmBreakpointKind,
    ) -> Result<(), SceError> {
        self.clear_step_breakpoint()?;

        let step = if is_debug_enabled() {
            let (value, control) = bp_value_control(addr, kind);
            sce_call!(ksceKernelSetTHBP(tid, 5, value, control))?;
            StepBreakpoint::Hw { tid, addr }
        } else {
            let bp = self.install_sw_breakpoint(self.pid(), addr, kind)?;
            StepBreakpoint::Sw { tid, bp }
        };
        *self.step.lock() = Some(step);
        Ok(())
    }

    fn clear_step_breakpoint(&self) -> Result<(), SceError> {
        let Some(step) = self.step.lock().take() else {
            return Ok(());
        };
        self.restore_step_breakpoint(step)
    }

    fn restore_step_breakpoint(&self, step: StepBreakpoint) -> Result<(), SceError> {
        match step {
            StepBreakpoint::Hw { tid, .. } => sce_call!(ksceKernelSetTHBP(tid, 5, 0, 0)).map(drop),
            StepBreakpoint::Sw { bp, .. } => self.restore_sw_breakpoint(self.pid(), &bp),
        }
    }

    pub fn is_step(&self, tid: SceUID, addr: u32) -> bool {
        self.step
            .lock()
            .as_ref()
            .is_some_and(|step| step.tid() == tid && step.addr() == addr)
    }

    pub fn step_finished(&self) {
        let Some(step) = self.step.lock().take() else {
            return;
        };
        let step_tid = step.tid();
        if let Err(err) = self.restore_step_breakpoint(step) {
            println!("step_finished: {err}");
        }
        *self.step_result.lock() = Some(step_tid);
        if let Some(evflag) = self.evflag() {
            let _ = evflag.set(EV_WAKE_WORKER);
        }
    }

    pub fn pop_step_finished(&self) -> Option<SceUID> {
        self.step_result.lock().take()
    }

    pub fn has_watchpoint(&self, addr: u32) -> bool {
        let wps = self.hw_watchpoints.lock();
        for slot in wps.iter() {
            if let Some(slot) = slot
                && slot.addr == addr
            {
                return true;
            };
        }
        false
    }

    pub fn set_hw_watchpoint(
        &self,
        addr: u32,
        _len: u32,
        kind: WatchKind,
    ) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        let pid = self.pid();
        let mut wps = self.hw_watchpoints.lock();

        for (idx, slot) in wps.iter_mut().enumerate() {
            let Some(slot) = slot else {
                continue;
            };
            if slot.addr == addr {
                if slot.kind != kind {
                    sce_call!(ksceKernelSetPHWP(pid, idx as _, addr, wp_control(kind)))?;
                    slot.kind = kind;
                }
                return Ok(true);
            }
        }

        for (idx, slot) in wps.iter_mut().enumerate() {
            if slot.is_none() {
                sce_call!(ksceKernelSetPHWP(pid, idx as _, addr, wp_control(kind)))?;
                *slot = Some(HwWatchpoint { addr, kind });
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn clear_hw_watchpoint(&self, addr: u32) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        let pid = self.pid();
        let mut wps = self.hw_watchpoints.lock();

        for (idx, slot) in wps.iter_mut().enumerate() {
            if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                sce_call!(ksceKernelSetPHWP(pid, idx as _, 0, 0))?;
                *slot = None;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn set_hw_breakpoint(&self, addr: u32, kind: ArmBreakpointKind) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        let pid = self.pid();
        let mut bps = self.hw_breakpoints.lock();

        for slot in bps.iter_mut() {
            if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                return Ok(true);
            }
        }

        for (idx, slot) in bps.iter_mut().enumerate() {
            if slot.is_none() {
                let (value, control) = bp_value_control(addr, kind);
                sce_call!(ksceKernelSetPHBP(pid, idx as _, value, control))?;
                *slot = Some(HwBreakpoint { addr });
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn clear_hw_breakpoint(&self, addr: u32) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        let pid = self.pid();
        let mut bps = self.hw_breakpoints.lock();

        for (idx, slot) in bps.iter_mut().enumerate() {
            if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                sce_call!(ksceKernelSetPHBP(pid, idx as _, 0, 0))?;
                *slot = None;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn set_sw_breakpoint(&self, addr: u32, kind: ArmBreakpointKind) -> bool {
        println!("set_sw_breakpoint addr={addr:x}");
        match self.try_set_sw_breakpoint(addr, kind) {
            Ok(()) => true,
            Err(err) => {
                println!("set_sw_breakpoint: {err}");
                false
            }
        }
    }

    pub fn clear_sw_breakpoint(&self, addr: u32) -> bool {
        println!("clear_sw_breakpoint addr={addr:x}");
        match self.try_clear_sw_breakpoint(addr) {
            Ok(found) => found,
            Err(err) => {
                println!("clear_sw_breakpoint: {err}");
                false
            }
        }
    }

    fn try_set_sw_breakpoint(&self, addr: u32, kind: ArmBreakpointKind) -> Result<(), SceError> {
        let Some(idx) = self.claim_sw_slot(addr) else {
            return Ok(());
        };
        let result = self.install_sw_breakpoint(self.pid(), addr, kind);
        let mut slots = self.sw_breakpoints.lock();
        match result {
            Ok(bp) => {
                slots[idx] = Some(bp);
                Ok(())
            }
            Err(err) => {
                slots[idx] = None;
                Err(err)
            }
        }
    }

    fn claim_sw_slot(&self, addr: u32) -> Option<usize> {
        let mut slots = self.sw_breakpoints.lock();
        if slots.iter().flatten().any(|bp| bp.addr() == addr) {
            return None;
        }
        if let Some(idx) = slots.iter().position(Option::is_none) {
            slots[idx] = Some(SwBreakpoint::Claimed { addr });
            return Some(idx);
        }
        None
    }

    fn install_sw_breakpoint(
        &self,
        pid: SceUID,
        addr: u32,
        kind: ArmBreakpointKind,
    ) -> Result<SwBreakpoint, SceError> {
        let patch = bkpt_insn(&kind);

        if is_shared_address(addr) {
            if !stai_is_loaded() {
                return Err(SceError::new(
                    -1,
                    "cant break in shared modules without stai",
                ));
            }
            let uid = sce_call!(staiCowWrite(pid, addr, patch.as_ptr() as _, patch.len()))?;
            return Ok(SwBreakpoint::Shared { addr, uid });
        }

        let len = match kind {
            ArmBreakpointKind::Arm32 | ArmBreakpointKind::Thumb32 => 4,
            ArmBreakpointKind::Thumb16 => 2,
        };
        let mut orig = [0u8; 4];
        read_user_process(pid, addr, &mut orig[..len])?;
        write_user_text(pid, addr, patch)?;
        Ok(SwBreakpoint::Patched { addr, orig, len })
    }

    fn try_clear_sw_breakpoint(&self, addr: u32) -> Result<bool, SceError> {
        let mut slots = self.sw_breakpoints.lock();

        let Some(idx) = slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|bp| bp.addr() == addr))
        else {
            return Ok(false);
        };

        if let Some(bp) = &slots[idx] {
            self.restore_sw_breakpoint(self.pid(), bp)?;
        }
        slots[idx] = None;
        Ok(true)
    }

    pub fn restore_sw_breakpoint(&self, pid: SceUID, bp: &SwBreakpoint) -> Result<(), SceError> {
        match *bp {
            SwBreakpoint::Claimed { .. } => Ok(()),
            SwBreakpoint::Patched { addr, orig, len } => write_user_text(pid, addr, &orig[..len]),
            SwBreakpoint::Shared { uid, .. } => sce_call!(staiCowRelease(uid)).map(drop),
        }
    }

    pub fn evflag(&self) -> Option<EventFlagRef> {
        unsafe { *self.evflag.get() }
    }
}

fn bkpt_insn(kind: &ArmBreakpointKind) -> &'static [u8] {
    match kind {
        ArmBreakpointKind::Thumb16 | ArmBreakpointKind::Thumb32 => {
            // bkpt #0: 0xBE00
            &[0x00u8, 0xbeu8]
        }
        ArmBreakpointKind::Arm32 => {
            // bkpt #0: 0xE1200070
            &[0x70u8, 0x00u8, 0x20u8, 0xE1u8]
        }
    }
}

pub fn find_session_for_pid(pid: SceUID) -> Option<&'static GdbSessionInner> {
    SESSION_POOL
        .iter()
        .find(|s| s.pid.load(Ordering::Acquire) == pid)
}

const DBGBCR_ENABLE: u32 = 1 << 0;
const DBGBCR_PMC_ANY: u32 = 0x3 << 1;
const DBGBCR_BAS_LOW_HALF: u32 = 0x3 << 5;
const DBGBCR_BAS_HIGH_HALF: u32 = 0xC << 5;
const DBGBCR_BAS_ALL: u32 = 0xF << 5;

fn bp_value_control(addr: u32, kind: ArmBreakpointKind) -> (u32, u32) {
    let bas = match kind {
        ArmBreakpointKind::Arm32 => DBGBCR_BAS_ALL,
        ArmBreakpointKind::Thumb16 | ArmBreakpointKind::Thumb32 => {
            if addr & 2 != 0 {
                DBGBCR_BAS_HIGH_HALF
            } else {
                DBGBCR_BAS_LOW_HALF
            }
        }
    };
    let addr = match kind {
        ArmBreakpointKind::Arm32 => addr,
        ArmBreakpointKind::Thumb16 | ArmBreakpointKind::Thumb32 => addr & !3,
    };
    (addr, DBGBCR_ENABLE | DBGBCR_PMC_ANY | bas)
}

fn wp_control(kind: WatchKind) -> u32 {
    let lsc: u32 = match kind {
        WatchKind::Read => 0b01,
        WatchKind::Write => 0b10,
        WatchKind::ReadWrite => 0b11,
    };
    DBGBCR_ENABLE | DBGBCR_PMC_ANY | (lsc << 3) | DBGBCR_BAS_ALL
}

fn is_shared_address(addr: u32) -> bool {
    Range::<u32> {
        start: 0xE0000000,
        end: 0xF0000000,
    }
    .contains(&addr)
}

pub struct GdbSession {
    inner: &'static GdbSessionInner,
}

impl GdbSession {
    pub fn new(flag: EventFlagRef, pid: SceUID) -> Option<Self> {
        let _guard = SESSION_ALLOC_LOCK.lock();
        for s in SESSION_POOL.iter() {
            if s.pid.load(Ordering::Acquire) == pid {
                return None;
            }
        }

        let slot = SESSION_POOL.iter().position(|s| {
            s.pid
                .compare_exchange(PID_UNUSED, pid, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })?;

        let Some(inner) = &SESSION_POOL.get(slot) else {
            return None;
        };
        unsafe {
            *inner.evflag.get() = Some(flag);
        }
        Some(Self { inner })
    }

    pub fn inner(&self) -> &'static GdbSessionInner {
        self.inner
    }

    pub fn set_hw_watchpoint(
        &self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        self.inner().set_hw_watchpoint(addr, len, kind)
    }

    pub fn clear_hw_watchpoint(&self, addr: u32) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        self.inner().clear_hw_watchpoint(addr)
    }

    pub fn set_hw_breakpoint(&self, addr: u32, kind: ArmBreakpointKind) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        self.inner().set_hw_breakpoint(addr, kind)
    }

    pub fn clear_hw_breakpoint(&self, addr: u32) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        self.inner().clear_hw_breakpoint(addr)
    }

    pub fn set_step(
        &self,
        tid: SceUID,
        addr: u32,
        kind: ArmBreakpointKind,
    ) -> Result<(), SceError> {
        self.inner.set_step(tid, addr, kind)
    }

    pub fn clear_all(&self) {
        let inner = self.inner();
        let pid = inner.pid.load(Ordering::Acquire);

        if let Err(err) = inner.clear_step_breakpoint() {
            println!("clear_step_breakpoint: {err}");
        }

        let mut bps = inner.hw_breakpoints.lock();
        for (idx, slot) in bps.iter_mut().enumerate() {
            if slot.is_some() {
                let _ = sce_call!(ksceKernelSetPHBP(pid, idx as _, 0, 0));
                *slot = None;
            }
        }

        let mut wps = inner.hw_watchpoints.lock();
        for (idx, slot) in wps.iter_mut().enumerate() {
            if slot.is_some() {
                let _ = sce_call!(ksceKernelSetPHWP(pid, idx as _, 0, 0));
                *slot = None;
            }
        }

        let mut sws = inner.sw_breakpoints.lock();
        for slot in sws.iter_mut() {
            if let Some(slot) = slot {
                let _ = inner.restore_sw_breakpoint(pid, slot);
            }
        }
    }
}

impl Drop for GdbSession {
    fn drop(&mut self) {
        self.clear_all();
        self.inner().reset();
    }
}
