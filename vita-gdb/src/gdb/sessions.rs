use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
};

use arrayvec::ArrayVec;
use gdbstub_arch::arm::ArmBreakpointKind;
use vitasdk_sys::SceUID;

use gdbstub::target::ext::breakpoints::WatchKind;

use crate::kernel::{event_flag::EventFlagRef, mpsc::MpscRing, spinlock::Spinlock};
use crate::{
    cp14::is_debug_enabled,
    kernel::{
        ffi::{ksceKernelCopyFromUserProc, sceKernelSetPHBP, sceKernelSetPHWP},
        utils::{SceError, write_user_text},
    },
};
use crate::{println, sce_call};

const MAX_SESSIONS: usize = 4;
const PID_UNUSED: i32 = -1;

pub const EV_WAKE_WORKER: u32 = 1 << 0;
pub const EV_WAKE_READER: u32 = 1 << 1;
pub const EV_PROCESS_STARTED: u32 = 1 << 4;

static SESSION_POOL: [GdbSessionInner; MAX_SESSIONS] =
    [const { GdbSessionInner::uninit() }; MAX_SESSIONS];

#[derive(Copy, Clone, Debug)]
pub enum ExceptionKind {
    Dabt,
    Pabt,
    Undef,
}

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
pub struct SwBreakpoint {
    addr: u32,
    orig: [u8; 4],
    patch_len: usize,
}

pub struct GdbSessionInner {
    pid: AtomicI32,
    evflag: UnsafeCell<Option<EventFlagRef>>,

    hw_breakpoints: Spinlock<[Option<HwBreakpoint>; 6]>,
    hw_watchpoints: Spinlock<[Option<HwWatchpoint>; 3]>,
    sw_breakpoints: Spinlock<[Option<SwBreakpoint>; 16]>,
    step: Spinlock<Option<(SceUID, u32)>>,
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

            hw_breakpoints: Spinlock::new([const { None }; 6]),
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
        self.exited.store(false, Ordering::Release);
        self.exceptions.clear();
        self.pid.store(PID_UNUSED, Ordering::Release);
    }

    pub fn pid(&self) -> Option<SceUID> {
        match self.pid.load(Ordering::Acquire) {
            PID_UNUSED => None,
            pid => Some(pid),
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

    pub fn set_step(&self, tid: SceUID, addr: u32) {
        *self.step.lock() = Some((tid, addr))
    }

    pub fn is_step(&self, addr: u32) -> bool {
        let Some((_step_tid, step_addr)) = *self.step.lock() else {
            return false;
        };
        step_addr == addr
    }

    pub fn step_finished(&self) {
        let Some((step_tid, step_addr)) = self.step.lock().take() else {
            return;
        };
        self.clear_sw_breakpoint(step_addr);
        *self.step_result.lock() = Some(step_tid);
        let evflag = self.evflag().unwrap();
        let _ = evflag.set(EV_WAKE_WORKER);
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
        let pid = self.pid().unwrap();
        let mut wps = self.hw_watchpoints.lock();

        for (idx, slot) in wps.iter_mut().enumerate() {
            let Some(slot) = slot else {
                continue;
            };
            if slot.kind != kind {
                sce_call!(sceKernelSetPHWP(pid, idx as _, addr, wp_control(kind)))?;
                slot.kind = kind;
            }
            return Ok(true);
        }

        for (idx, slot) in wps.iter_mut().enumerate() {
            if slot.is_none() {
                sce_call!(sceKernelSetPHWP(pid, idx as _, addr, wp_control(kind)))?;
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
        let pid = self.pid().unwrap();
        let mut wps = self.hw_watchpoints.lock();

        for (idx, slot) in wps.iter_mut().enumerate() {
            if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                sce_call!(sceKernelSetPHWP(pid, idx as _, 0, 0))?;
                *slot = None;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn set_hw_breakpoint(&self, addr: u32) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        let pid = self.pid().unwrap();
        let mut bps = self.hw_breakpoints.lock();

        for slot in bps.iter_mut() {
            if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                return Ok(true);
            }
        }

        for (idx, slot) in bps.iter_mut().enumerate() {
            if slot.is_none() {
                sce_call!(sceKernelSetPHBP(pid, idx as _, addr, bp_control()))?;
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
        let pid = self.pid().unwrap();
        let mut bps = self.hw_breakpoints.lock();

        for (idx, slot) in bps.iter_mut().enumerate() {
            if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                sce_call!(sceKernelSetPHBP(pid, idx as _, 0, 0))?;
                *slot = None;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn set_sw_breakpoint(&self, addr: u32, kind: ArmBreakpointKind) -> bool {
        println!("set_sw_breakpoint addr={addr:x}");
        let Some(pid) = self.pid() else {
            return false;
        };

        if is_shared_address(addr) {
            println!("cant sw break in shared libraries (yet?)");
            return false;
        }

        let patch_len = match kind {
            ArmBreakpointKind::Thumb16 => 2,
            _ => 4,
        };

        let mut orig = [0u8; 4];
        if let Err(err) = sce_call!(ksceKernelCopyFromUserProc(
            pid,
            orig.as_mut_ptr() as _,
            addr as _,
            patch_len
        )) {
            println!("set_sw_breakpoint: {err}");
            return false;
        }
        println!("orig={orig:?}");

        let mut claimed: Option<usize> = None;
        {
            let mut sw = self.sw_breakpoints.lock();
            for slot in sw.iter_mut() {
                if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                    return true;
                }
            }
            for (idx, slot) in sw.iter_mut().enumerate() {
                if slot.is_none() {
                    *slot = Some(SwBreakpoint {
                        addr,
                        orig,
                        patch_len,
                    });
                    claimed = Some(idx);
                    break;
                }
            }
        }
        let Some(claimed) = claimed else {
            return false;
        };

        let patched: &[u8] = match kind {
            gdbstub_arch::arm::ArmBreakpointKind::Thumb16 => {
                // bkpt #0: 0xBE00
                &[0x00u8, 0xbeu8]
            }
            _ => {
                // bkpt #0: 0xE1200070
                &[0x70u8, 0x00u8, 0x20u8, 0xE1u8]
            }
        };
        println!("patched={patched:?}");

        match write_user_text(pid, addr, patched) {
            Ok(_) => true,
            Err(err) => {
                println!("set_sw_breakpoint: {err}");
                let mut sw = self.sw_breakpoints.lock();
                sw[claimed] = None;
                false
            }
        }
    }

    pub fn clear_sw_breakpoint(&self, addr: u32) -> bool {
        let Some(pid) = self.pid() else {
            return false;
        };
        println!("clear_sw_breakpoint addr={addr:x}");
        let mut sws = self.sw_breakpoints.lock();
        for slot in sws.iter_mut() {
            if slot.as_ref().is_some_and(|slot| slot.addr == addr) {
                if let Err(err) = self.restore_sw_slot(pid, slot) {
                    println!("restore_sw_slot: {err}");
                    return false;
                }
                *slot = None;
                return true;
            }
        }
        false
    }

    pub fn restore_sw_slot(
        &self,
        pid: SceUID,
        slot: &mut Option<SwBreakpoint>,
    ) -> Result<(), SceError> {
        let Some(slot) = slot.take() else {
            return Ok(());
        };
        write_user_text(pid, slot.addr, &slot.orig.as_slice()[0..slot.patch_len])?;
        Ok(())
    }

    pub fn evflag(&self) -> Option<EventFlagRef> {
        unsafe { *self.evflag.get() }
    }
}

pub fn find_session_for_pid(pid: SceUID) -> Option<&'static GdbSessionInner> {
    SESSION_POOL
        .iter()
        .find(|s| s.pid.load(Ordering::Acquire) == pid)
}

fn bp_control() -> u32 {
    (1 << 0) | (0x3 << 1) | (0xF << 5) | (0x1 << 14) | (0x0 << 20)
}

fn wp_control(kind: WatchKind) -> u32 {
    let lsc: u32 = match kind {
        WatchKind::Read => 0b01,
        WatchKind::Write => 0b10,
        WatchKind::ReadWrite => 0b11,
    };
    1 | (1 << 1) | (lsc << 3) | (0xF << 5) | (0x1 << 14) | (0 << 20) | (0 << 24)
}

fn is_shared_address(addr: u32) -> bool {
    addr >= 0xE0000000 && addr < 0xF0000000
}

pub struct GdbSession {
    inner: &'static GdbSessionInner,
}

impl GdbSession {
    pub fn new(flag: EventFlagRef, pid: SceUID) -> Option<Self> {
        let slot = SESSION_POOL.iter().position(|s| {
            s.pid
                .compare_exchange(PID_UNUSED, pid, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })?;

        let inner = &SESSION_POOL[slot];
        unsafe {
            *inner.evflag.get() = Some(flag);
        }
        Some(Self { inner })
    }

    pub fn inner(&self) -> &'static GdbSessionInner {
        self.inner
    }

    pub fn pid(&self) -> Option<SceUID> {
        self.inner().pid()
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

    pub fn set_hw_breakpoint(&self, addr: u32) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        self.inner().set_hw_breakpoint(addr)
    }

    pub fn clear_hw_breakpoint(&self, addr: u32) -> Result<bool, SceError> {
        if !is_debug_enabled() {
            return Ok(false);
        }
        self.inner().clear_hw_breakpoint(addr)
    }

    pub fn set_step(&self, tid: SceUID, addr: u32) -> Result<(), SceError> {
        self.inner.set_step(tid, addr);
        Ok(())
    }

    pub fn clear_all(&self) {
        let inner = self.inner();
        let pid = inner.pid.load(Ordering::Acquire);

        let mut bps = inner.hw_breakpoints.lock();
        for (idx, slot) in bps.iter_mut().enumerate() {
            if slot.is_some() {
                let _ = sce_call!(sceKernelSetPHBP(pid, idx as _, 0, 0));
                *slot = None;
            }
        }

        let mut wps = inner.hw_watchpoints.lock();
        for (idx, slot) in wps.iter_mut().enumerate() {
            if slot.is_some() {
                let _ = sce_call!(sceKernelSetPHWP(pid, idx as _, 0, 0));
            }
        }

        let mut sws = inner.sw_breakpoints.lock();
        for slot in sws.iter_mut() {
            if slot.is_some() {
                let _ = inner.restore_sw_slot(pid, slot);
            }
        }
    }

    pub fn dump_state(&self) -> DumpState {
        let inner = self.inner();

        let mut hw_breakpoints = ArrayVec::new();
        for bp in &*inner.hw_breakpoints.lock() {
            let Some(bp) = bp else {
                continue;
            };
            hw_breakpoints.push(bp.addr);
        }

        let mut hw_watchpoints = ArrayVec::new();
        for wp in &*inner.hw_watchpoints.lock() {
            let Some(wp) = wp else {
                continue;
            };
            hw_watchpoints.push(wp.addr);
        }

        let mut sw_breakpoints = ArrayVec::new();
        for sw in &*inner.sw_breakpoints.lock() {
            let Some(sw) = sw else {
                continue;
            };
            sw_breakpoints.push(sw.addr);
        }

        DumpState {
            pid: inner.pid(),
            hw_breakpoints,
            hw_watchpoints,
            sw_breakpoints,
        }
    }
}

pub struct DumpState {
    pub pid: Option<SceUID>,
    pub hw_breakpoints: ArrayVec<u32, 6>,
    pub hw_watchpoints: ArrayVec<u32, 3>,
    pub sw_breakpoints: ArrayVec<u32, 16>,
}

impl Drop for GdbSession {
    fn drop(&mut self) {
        self.clear_all();
        self.inner().reset();
    }
}
