use core::ops::Range;

use gdbstub_arch::arm::ArmBreakpointKind;
use vitasdk_sys::SceUID;

use gdbstub::target::ext::breakpoints::WatchKind;

use crate::kernel::{
    event_flag::EventFlagRef,
    ffi::{stai_is_loaded, staiCowRelease, staiCowWrite},
    mpsc::MpscRing,
    spinlock::{Spinlock, SpinlockGuard},
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

pub const EV_WAKE_WORKER: u32 = 1 << 0;
pub const EV_WAKE_READER: u32 = 1 << 1;

static SESSION_POOL: [Spinlock<Option<GdbSessionInner>>; MAX_SESSIONS] =
    [const { Spinlock::new(None) }; MAX_SESSIONS];
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
    pid: SceUID,
    evflag: EventFlagRef,

    hw_breakpoints: [Option<HwBreakpoint>; 5],
    hw_watchpoints: [Option<HwWatchpoint>; 3],
    sw_breakpoints: [Option<SwBreakpoint>; 16],
    step: Option<StepBreakpoint>,
    step_result: Option<SceUID>,
    exited: bool,
    exceptions: MpscRing<ExceptionEvent, 8>,
}

impl GdbSessionInner {
    fn new(pid: SceUID, evflag: EventFlagRef) -> Self {
        Self {
            pid,
            evflag,

            hw_breakpoints: [const { None }; 5],
            hw_watchpoints: [const { None }; 3],
            sw_breakpoints: [const { None }; 16],
            step: None,
            step_result: None,
            exited: false,
            exceptions: MpscRing::new(),
        }
    }

    pub fn reset(&mut self) {
        let _ = self.evflag.clear(EV_WAKE_WORKER);
        self.hw_breakpoints.fill(None);
        self.hw_watchpoints.fill(None);
        self.sw_breakpoints.fill(None);
        self.step = None;
        self.step_result = None;
        self.exited = false;
        unsafe {
            self.exceptions.clear();
        }
    }

    pub fn pid(&self) -> SceUID {
        self.pid
    }

    pub fn pop_excp(&mut self) -> Option<ExceptionEvent> {
        unsafe { self.exceptions.pop() }
    }

    pub fn has_excp(&self) -> bool {
        !self.exceptions.is_empty()
    }

    pub fn pop_exited(&mut self) -> bool {
        let exited = self.exited;
        self.exited = false;
        exited
    }

    pub fn set_step(
        &mut self,
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
            let bp = Self::install_sw_breakpoint(self.pid, addr, kind)?;
            StepBreakpoint::Sw { tid, bp }
        };
        self.step = Some(step);
        Ok(())
    }

    fn clear_step_breakpoint(&mut self) -> Result<(), SceError> {
        let Some(step) = self.step.take() else {
            return Ok(());
        };
        Self::restore_step_breakpoint(self.pid, step)
    }

    fn restore_step_breakpoint(pid: SceUID, step: StepBreakpoint) -> Result<(), SceError> {
        match step {
            StepBreakpoint::Hw { tid, .. } => sce_call!(ksceKernelSetTHBP(tid, 5, 0, 0)).map(drop),
            StepBreakpoint::Sw { bp, .. } => Self::restore_sw_breakpoint(pid, &bp),
        }
    }

    pub fn is_step(&self, tid: SceUID, addr: u32) -> bool {
        self.step
            .as_ref()
            .is_some_and(|step| step.tid() == tid && step.addr() == addr)
    }

    pub fn pop_step_finished(&mut self) -> Option<SceUID> {
        self.step_result.take()
    }

    pub fn has_watchpoint(&self, addr: u32) -> bool {
        self.hw_watchpoints
            .iter()
            .flatten()
            .any(|slot| slot.addr == addr)
    }

    pub fn set_hw_watchpoint(
        &mut self,
        addr: u32,
        _len: u32,
        kind: WatchKind,
    ) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        let pid = self.pid;

        for (idx, slot) in self.hw_watchpoints.iter_mut().enumerate() {
            let Some(wp) = slot else {
                continue;
            };
            if wp.addr == addr {
                if wp.kind != kind {
                    sce_call!(ksceKernelSetPHWP(pid, idx as _, addr, wp_control(kind)))?;
                    wp.kind = kind;
                }
                return Ok(true);
            }
        }

        for (idx, slot) in self.hw_watchpoints.iter_mut().enumerate() {
            if slot.is_none() {
                sce_call!(ksceKernelSetPHWP(pid, idx as _, addr, wp_control(kind)))?;
                *slot = Some(HwWatchpoint { addr, kind });
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn clear_hw_watchpoint(&mut self, addr: u32) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        let pid = self.pid;

        for (idx, slot) in self.hw_watchpoints.iter_mut().enumerate() {
            if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                sce_call!(ksceKernelSetPHWP(pid, idx as _, 0, 0))?;
                *slot = None;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn set_hw_breakpoint(
        &mut self,
        addr: u32,
        kind: ArmBreakpointKind,
    ) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        let pid = self.pid;

        for slot in self.hw_breakpoints.iter_mut() {
            if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                return Ok(true);
            }
        }

        for (idx, slot) in self.hw_breakpoints.iter_mut().enumerate() {
            if slot.is_none() {
                let (value, control) = bp_value_control(addr, kind);
                sce_call!(ksceKernelSetPHBP(pid, idx as _, value, control))?;
                *slot = Some(HwBreakpoint { addr });
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn clear_hw_breakpoint(&mut self, addr: u32) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        let pid = self.pid;

        for (idx, slot) in self.hw_breakpoints.iter_mut().enumerate() {
            if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                sce_call!(ksceKernelSetPHBP(pid, idx as _, 0, 0))?;
                *slot = None;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn clear_sw_breakpoint(&mut self, addr: u32) -> bool {
        println!("clear_sw_breakpoint addr={addr:x}");
        match self.try_clear_sw_breakpoint(addr) {
            Ok(found) => found,
            Err(err) => {
                println!("clear_sw_breakpoint: {err}");
                false
            }
        }
    }

    fn finish_sw_slot(&mut self, idx: usize, result: Result<SwBreakpoint, SceError>) -> bool {
        let Some(slot) = self.sw_breakpoints.get_mut(idx) else {
            return false;
        };
        match result {
            Ok(bp) => {
                *slot = Some(bp);
                true
            }
            Err(err) => {
                println!("set_sw_breakpoint: {err}");
                *slot = None;
                false
            }
        }
    }

    fn claim_sw_slot(&mut self, addr: u32) -> Option<usize> {
        if self
            .sw_breakpoints
            .iter()
            .flatten()
            .any(|bp| bp.addr() == addr)
        {
            return None;
        }
        if let Some(idx) = self.sw_breakpoints.iter().position(Option::is_none) {
            let slot = self.sw_breakpoints.get_mut(idx)?;
            *slot = Some(SwBreakpoint::Claimed { addr });
            return Some(idx);
        }
        None
    }

    fn install_sw_breakpoint(
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
        let buf = orig.get_mut(..len).ok_or(SceError::new(-1, "invalid"))?;
        read_user_process(pid, addr, buf)?;
        write_user_text(pid, addr, patch)?;
        Ok(SwBreakpoint::Patched { addr, orig, len })
    }

    fn try_clear_sw_breakpoint(&mut self, addr: u32) -> Result<bool, SceError> {
        for slot in self.sw_breakpoints.iter_mut() {
            if let Some(bp) = slot.as_ref()
                && bp.addr() == addr
            {
                Self::restore_sw_breakpoint(self.pid, bp)?;
                *slot = None;
                return Ok(true);
            };
        }
        Ok(false)
    }

    fn restore_sw_breakpoint(pid: SceUID, bp: &SwBreakpoint) -> Result<(), SceError> {
        match *bp {
            SwBreakpoint::Claimed { .. } => Ok(()),
            SwBreakpoint::Patched { addr, orig, len } => {
                let Some(buf) = orig.get(..len) else {
                    return Ok(());
                };
                write_user_text(pid, addr, buf)
            }
            SwBreakpoint::Shared { uid, .. } => sce_call!(staiCowRelease(uid)).map(drop),
        }
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

#[derive(Clone, Copy)]
pub struct SessionRef {
    slot: &'static Spinlock<Option<GdbSessionInner>>,
}

impl SessionRef {
    fn lock(&self) -> SpinlockGuard<'static, Option<GdbSessionInner>> {
        self.slot.lock()
    }

    pub fn pid(&self) -> SceUID {
        self.lock().as_ref().map_or(-1, GdbSessionInner::pid)
    }

    pub fn push_excp(&self, event: ExceptionEvent) {
        let (evflag, overflow) = {
            let mut slot = self.lock();
            let Some(inner) = slot.as_mut() else {
                return;
            };
            let overflow = !inner.exceptions.push(event);
            (inner.evflag, overflow)
        };
        if overflow {
            println!("exceptions overflow");
        }
        let _ = evflag.set(EV_WAKE_WORKER);
    }

    pub fn pop_excp(&self) -> Option<ExceptionEvent> {
        self.lock().as_mut().and_then(GdbSessionInner::pop_excp)
    }

    pub fn has_excp(&self) -> bool {
        self.lock().as_ref().is_some_and(GdbSessionInner::has_excp)
    }

    pub fn push_exited(&self) {
        let evflag = {
            let mut slot = self.lock();
            let Some(inner) = slot.as_mut() else {
                return;
            };
            inner.exited = true;
            inner.evflag
        };
        let _ = evflag.set(EV_WAKE_WORKER);
    }

    pub fn pop_exited(&self) -> bool {
        self.lock()
            .as_mut()
            .is_some_and(GdbSessionInner::pop_exited)
    }

    pub fn has_watchpoint(&self, addr: u32) -> bool {
        self.lock()
            .as_ref()
            .is_some_and(|inner| inner.has_watchpoint(addr))
    }

    pub fn is_step(&self, tid: SceUID, addr: u32) -> bool {
        self.lock()
            .as_ref()
            .is_some_and(|inner| inner.is_step(tid, addr))
    }

    pub fn step_finished(&self) {
        let (step, pid, evflag) = {
            let mut slot = self.lock();
            let Some(inner) = slot.as_mut() else {
                return;
            };
            let Some(step) = inner.step.take() else {
                return;
            };
            inner.step_result = Some(step.tid());
            (step, inner.pid, inner.evflag)
        };
        if let Err(err) = GdbSessionInner::restore_step_breakpoint(pid, step) {
            println!("step_finished: {err}");
        }
        let _ = evflag.set(EV_WAKE_WORKER);
    }

    pub fn pop_step_finished(&self) -> Option<SceUID> {
        self.lock()
            .as_mut()
            .and_then(GdbSessionInner::pop_step_finished)
    }

    pub fn set_hw_watchpoint(
        &self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> Result<bool, SceError> {
        println!("set_hw_watchpoint addr={addr:x}");
        match self.lock().as_mut() {
            Some(inner) => inner.set_hw_watchpoint(addr, len, kind),
            None => Ok(false),
        }
    }

    pub fn clear_hw_watchpoint(&self, addr: u32) -> Result<bool, SceError> {
        match self.lock().as_mut() {
            Some(inner) => inner.clear_hw_watchpoint(addr),
            None => Ok(false),
        }
    }

    pub fn set_hw_breakpoint(&self, addr: u32, kind: ArmBreakpointKind) -> Result<bool, SceError> {
        println!("set_hw_breakpoint addr={addr:x}");
        match self.lock().as_mut() {
            Some(inner) => inner.set_hw_breakpoint(addr, kind),
            None => Ok(false),
        }
    }

    pub fn clear_hw_breakpoint(&self, addr: u32) -> Result<bool, SceError> {
        match self.lock().as_mut() {
            Some(inner) => inner.clear_hw_breakpoint(addr),
            None => Ok(false),
        }
    }

    pub fn set_sw_breakpoint(&self, addr: u32, kind: ArmBreakpointKind) -> bool {
        println!("set_sw_breakpoint addr={addr:x}");
        let (pid, idx) = {
            let mut slot = self.lock();
            let Some(inner) = slot.as_mut() else {
                return false;
            };
            let Some(idx) = inner.claim_sw_slot(addr) else {
                return true;
            };
            (inner.pid, idx)
        };
        let result = GdbSessionInner::install_sw_breakpoint(pid, addr, kind);
        let mut slot = self.lock();
        let Some(inner) = slot.as_mut() else {
            return false;
        };
        inner.finish_sw_slot(idx, result)
    }

    pub fn clear_sw_breakpoint(&self, addr: u32) -> bool {
        match self.lock().as_mut() {
            Some(inner) => inner.clear_sw_breakpoint(addr),
            None => false,
        }
    }

    pub fn set_step(
        &self,
        tid: SceUID,
        addr: u32,
        kind: ArmBreakpointKind,
    ) -> Result<(), SceError> {
        match self.lock().as_mut() {
            Some(inner) => inner.set_step(tid, addr, kind),
            None => Err(SceError::new(-1, "no session")),
        }
    }
}

pub fn find_session_for_pid(pid: SceUID) -> Option<SessionRef> {
    SESSION_POOL.iter().find_map(|slot| {
        let found = slot.lock().as_ref().is_some_and(|inner| inner.pid() == pid);
        found.then_some(SessionRef { slot })
    })
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
    inner: SessionRef,
}

impl GdbSession {
    pub fn new(pid: SceUID, evflag: EventFlagRef) -> Option<Self> {
        let _guard = SESSION_ALLOC_LOCK.lock();
        if SESSION_POOL
            .iter()
            .any(|slot| slot.lock().as_ref().is_some_and(|inner| inner.pid == pid))
        {
            return None;
        }
        let slot = SESSION_POOL.iter().find(|slot| slot.lock().is_none())?;
        *slot.lock() = Some(GdbSessionInner::new(pid, evflag));
        Some(Self {
            inner: SessionRef { slot },
        })
    }

    pub fn inner(&self) -> SessionRef {
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
        let mut slot = self.inner.lock();
        let Some(inner) = slot.as_mut() else {
            return;
        };
        let pid = inner.pid;

        if let Err(err) = inner.clear_step_breakpoint() {
            println!("clear_step_breakpoint: {err}");
        }

        for (idx, slot) in inner.hw_breakpoints.iter_mut().enumerate() {
            if slot.is_some() {
                let _ = sce_call!(ksceKernelSetPHBP(pid, idx as _, 0, 0));
                *slot = None;
            }
        }

        for (idx, slot) in inner.hw_watchpoints.iter_mut().enumerate() {
            if slot.is_some() {
                let _ = sce_call!(ksceKernelSetPHWP(pid, idx as _, 0, 0));
                *slot = None;
            }
        }

        for slot in inner.sw_breakpoints.iter_mut() {
            if let Some(bp) = slot {
                let _ = GdbSessionInner::restore_sw_breakpoint(pid, bp);
            }
            *slot = None;
        }
    }
}

impl Drop for GdbSession {
    fn drop(&mut self) {
        self.clear_all();
        if let Some(mut inner) = self.inner.slot.lock().take() {
            inner.reset();
        }
    }
}
