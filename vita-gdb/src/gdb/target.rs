use arrayvec::ArrayVec;
use core::{ffi::CStr, fmt::Write, mem::zeroed, ptr::null_mut};
use gdbstub::{
    common::Pid,
    target::{
        Target, TargetError, TargetResult,
        ext::{
            base::BaseOps,
            breakpoints::{
                Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps, HwWatchpoint,
                HwWatchpointOps, SwBreakpoint, SwBreakpointOps, WatchKind,
            },
            exec_file::{ExecFile, ExecFileOps},
            extended_mode::{
                Args, AttachKind, CurrentActivePid, CurrentActivePidOps, ExtendedMode,
                ExtendedModeOps, ShouldTerminate,
            },
            libraries::{Libraries, LibrariesOps},
            monitor_cmd::MonitorCmdOps,
            process_info::{ProcessInfo, ProcessInfoOps, ProcessInfoResponse},
        },
    },
};
use gdbstub_arch::arm::ArmBreakpointKind;
use vitasdk_sys::{
    SCE_EVENT_WAITCLEAR_PAT, SceAppMgrLaunchParam, SceUID, ksceAppMgrKillProcess,
    ksceAppMgrLaunchAppByPath,
};

use crate::{
    cp14::is_debug_enabled,
    gdb::{
        armv7::Armv7,
        sessions::{EV_PROCESS_STARTED, GdbSession},
    },
    kernel::{
        event_flag::EventFlagRef,
        ffi::ksceKernelGetModuleIdByPid,
        utils::{
            ArgvWriter, SceError, StreamWriter, get_module_ids, get_module_info, get_process_ids,
            halt_process, resume_process,
        },
    },
    println, sce_call,
};

const FAKE_PID: Pid = const { Pid::new(1).unwrap() };

pub struct VitaTarget {
    pub(crate) session: Option<GdbSession>,
    pub(crate) evflag: EventFlagRef,
    pub(crate) detached: bool,
    pub(crate) attach_kind: AttachKind,
    pub(crate) step_action: Option<SceUID>,
    pub(crate) continue_actions: ArrayVec<SceUID, 64>,
    pub(crate) scheduler_lock: bool,
}

impl VitaTarget {
    pub fn new(evflag: EventFlagRef) -> VitaTarget {
        VitaTarget {
            session: None,
            evflag,
            detached: false,
            attach_kind: AttachKind::Attach,
            step_action: None,
            continue_actions: ArrayVec::new(),
            scheduler_lock: false,
        }
    }

    pub fn pid(&self) -> Option<SceUID> {
        if let Some(session) = self.session.as_ref() {
            return session.pid();
        }
        None
    }

    pub fn attach(&mut self, pid: SceUID, kind: AttachKind) -> bool {
        if self.session.is_some() {
            println!("already attached");
            return false;
        }
        let Some(session) = GdbSession::new(self.evflag, pid) else {
            println!("no free gdb session slots");
            return false;
        };
        self.session = Some(session);
        self.detached = false;
        self.attach_kind = kind;
        true
    }

    pub fn detach(&mut self) {
        if let Some(session) = self.session.take() {
            session.clear_all();
            if let Some(pid) = session.pid() {
                let _ = resume_process(pid);
            }
            self.detached = true;
        }
    }
}

impl Drop for VitaTarget {
    fn drop(&mut self) {
        self.detach();
    }
}

impl Target for VitaTarget {
    type Arch = Armv7;
    type Error = SceError;

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::MultiThread(self)
    }

    #[inline(always)]
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_monitor_cmd(&mut self) -> Option<MonitorCmdOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_extended_mode(&mut self) -> Option<ExtendedModeOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_libraries(&mut self) -> Option<LibrariesOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_process_info(&mut self) -> Option<ProcessInfoOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_exec_file(&mut self) -> Option<ExecFileOps<'_, Self>> {
        Some(self)
    }
}

impl ExtendedMode for VitaTarget {
    #[inline(always)]
    fn support_current_active_pid(&mut self) -> Option<CurrentActivePidOps<'_, Self>> {
        Some(self)
    }

    fn attach(&mut self, new_pid: Pid) -> TargetResult<(), Self> {
        let pid = new_pid.get() as SceUID;
        if new_pid == FAKE_PID || pid == 0x10005 {
            return Err(TargetError::NonFatal);
        }

        self.detach();
        if !self.attach(pid, AttachKind::Attach) {
            return Err(TargetError::NonFatal);
        }

        if let Err(err) = halt_process(pid) {
            println!("attach: halt of pid {pid} {err}");
            return Err(TargetError::NonFatal);
        }
        Ok(())
    }

    fn kill(&mut self, pid: Option<Pid>) -> TargetResult<ShouldTerminate, Self> {
        let Some(pid) = pid.map(|pid| pid.get() as i32).or(self.pid()) else {
            return Err(TargetError::NonFatal);
        };
        if let Err(err) = sce_call!(ksceAppMgrKillProcess(pid)) {
            println!("kill: {err}");
            return Err(TargetError::NonFatal);
        };
        Ok(ShouldTerminate::No)
    }

    fn restart(&mut self) -> Result<(), Self::Error> {
        unimplemented!("never called");
    }

    fn query_if_attached(&mut self, pid: Pid) -> TargetResult<AttachKind, Self> {
        let Some(cur_pid) = self.pid() else {
            return Err(TargetError::NonFatal);
        };
        if cur_pid != pid.get() as SceUID {
            return Err(TargetError::NonFatal);
        }
        Ok(match self.attach_kind {
            AttachKind::Attach => AttachKind::Attach,
            AttachKind::Run => AttachKind::Run,
        })
    }

    fn run(&mut self, filename: Option<&[u8]>, _args: Args<'_, '_>) -> TargetResult<Pid, Self> {
        let Some(filename) = filename else {
            println!("run: no filename");
            return Err(TargetError::NonFatal);
        };
        let filename = match str::from_utf8(filename) {
            Ok(filename) => filename,
            Err(err) => {
                println!("run filename invalid: {err}");
                return Err(TargetError::NonFatal);
            }
        };

        let mut titleid = "MLCL05505";
        let mut path_buf = [0u8; 128];
        let mut writer = StreamWriter::new(&mut path_buf, 0);
        if filename.len() == 9 {
            let _ = write!(writer, "ux0:app/{filename}/eboot.bin");
            titleid = filename;
        } else {
            let _ = write!(writer, "{filename}");
        }
        let executable_path: &CStr = writer.into_cstr().map_err(|_| {
            println!("filename too long");
            TargetError::NonFatal
        })?;

        // TODO: doesnt get set correctly
        let mut launch_args = ArgvWriter::new();
        launch_args.add("-titleid", titleid);
        let launch_args = launch_args.to_slice();

        let pid = sce_call!(ksceAppMgrLaunchAppByPath(
            executable_path.as_ptr(),
            launch_args.as_ptr() as _,
            launch_args.len() as _,
            0x80000000,
            &SceAppMgrLaunchParam {
                size: size_of::<SceAppMgrLaunchParam>() as u32,
                unk_4: 1 << 31,
                ..zeroed()
            },
            null_mut(),
        ))
        .map_err(|err| {
            println!("run: {err}");
            TargetError::NonFatal
        })?;

        self.detach();
        if !self.attach(pid, AttachKind::Run) {
            return Err(TargetError::NonFatal);
        }

        // wait for launch
        if let Err(err) = match self.evflag.wait_timeout(
            EV_PROCESS_STARTED,
            SCE_EVENT_WAITCLEAR_PAT,
            10 * 1000 * 1000,
        ) {
            Ok(Some(_)) => Ok(()),
            Err(err) => {
                println!("run wait: {err}");
                Err(TargetError::NonFatal)
            }
            Ok(None) => {
                println!("run wait timeout");
                Err(TargetError::NonFatal)
            }
        } {
            self.detach();
            return Err(err);
        }

        let pid = Pid::new(pid as _).ok_or(TargetError::NonFatal)?;
        Ok(pid)
    }
}

impl CurrentActivePid for VitaTarget {
    fn current_active_pid(&mut self) -> Result<Pid, Self::Error> {
        Ok(match self.pid() {
            Some(pid) => Pid::new(pid as usize).unwrap(),
            None => FAKE_PID,
        })
    }
}

impl Libraries for VitaTarget {
    fn get_libraries(
        &self,
        offset: u64,
        _length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let Some(pid) = self.pid() else {
            return Ok(0);
        };

        let modids = match get_module_ids(pid) {
            Ok(modids) => modids,
            Err(err) => {
                println!("{err} pid={pid}");
                return Err(TargetError::NonFatal);
            }
        };

        let mut writer = StreamWriter::new(buf, offset as _);
        let _ = write!(writer, r#"<library-list version="1.0">"#);
        for modid in modids {
            let info = match get_module_info(pid, modid) {
                Ok(info) => info,
                Err(err) => {
                    println!("{err} pid={pid} modid={modid}");
                    continue;
                }
            };
            let Ok(path) = unsafe { CStr::from_ptr(info.path.as_ptr() as _) }.to_str() else {
                continue;
            };
            let _ = write!(writer, r#"<library name="{}">"#, path);
            for seg in info.segments.iter() {
                if seg.size == 0 {
                    break;
                }
                let _ = write!(writer, r#"<segment address="0x{:x}"/>"#, seg.vaddr as u32);
            }
            let _ = write!(writer, "</library>");
        }
        let _ = write!(writer, "</library-list>");
        Ok(writer.written())
    }
}

impl ProcessInfo for VitaTarget {
    #[inline(always)]
    fn process_info(
        &self,
        write_item: &mut dyn FnMut(&ProcessInfoResponse<'_>),
    ) -> Result<(), Self::Error> {
        for pid in get_process_ids()? {
            if let Some(pid) = Pid::new(pid as _) {
                write_item(&ProcessInfoResponse::Pid(pid));
            }
        }
        Ok(())
    }
}

impl ExecFile for VitaTarget {
    fn get_exec_file(
        &self,
        pid: Option<Pid>,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let Some(pid) = pid.map(|pid| pid.get() as i32).or(self.pid()) else {
            return Err(TargetError::NonFatal);
        };
        let modid = match sce_call!(ksceKernelGetModuleIdByPid(pid)) {
            Ok(modid) => modid,
            Err(err) => {
                println!("get_exec_file {err}");
                return Err(TargetError::NonFatal);
            }
        };
        let info = match get_module_info(pid, modid) {
            Ok(modid) => modid,
            Err(err) => {
                println!("get_exec_file {err}");
                return Err(TargetError::NonFatal);
            }
        };

        let path = unsafe { core::slice::from_raw_parts(info.path.as_ptr() as _, info.path.len()) };
        let path_len = path.len();
        let offset = offset as usize;
        let copy_len = length.min(buf.len());
        if offset >= path_len || copy_len == 0 {
            return Ok(0);
        }
        let count = (path_len - offset).min(copy_len);
        buf[..count].copy_from_slice(&path[offset..offset + count]);
        Ok(count)
    }
}

impl Breakpoints for VitaTarget {
    #[inline(always)]
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<'_, Self>> {
        if is_debug_enabled() { Some(self) } else { None }
    }

    #[inline(always)]
    fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>> {
        if is_debug_enabled() { Some(self) } else { None }
    }

    #[inline(always)]
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl SwBreakpoint for VitaTarget {
    fn add_sw_breakpoint(
        &mut self,
        addr: u32,
        kind: ArmBreakpointKind,
    ) -> TargetResult<bool, Self> {
        let Some(session) = self.session.as_ref() else {
            return Ok(false);
        };
        Ok(session.inner().set_sw_breakpoint(addr, kind))
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u32,
        _kind: ArmBreakpointKind,
    ) -> TargetResult<bool, Self> {
        let Some(session) = self.session.as_ref() else {
            return Ok(false);
        };
        Ok(session.inner().clear_sw_breakpoint(addr))
    }
}

impl HwBreakpoint for VitaTarget {
    fn add_hw_breakpoint(
        &mut self,
        addr: u32,
        _kind: ArmBreakpointKind,
    ) -> TargetResult<bool, Self> {
        let Some(session) = self.session.as_ref() else {
            return Ok(false);
        };
        if let Err(err) = session.set_hw_breakpoint(addr) {
            println!("set_hw_breakpoint: {err}");
            return Ok(false);
        };
        Ok(true)
    }

    fn remove_hw_breakpoint(
        &mut self,
        addr: u32,
        _kind: ArmBreakpointKind,
    ) -> TargetResult<bool, Self> {
        let Some(session) = self.session.as_ref() else {
            return Ok(false);
        };
        if let Err(err) = session.clear_hw_breakpoint(addr) {
            println!("clear_hw_breakpoint: {err}");
            return Ok(false);
        };
        Ok(true)
    }
}

impl HwWatchpoint for VitaTarget {
    fn add_hw_watchpoint(
        &mut self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let Some(session) = self.session.as_ref() else {
            return Ok(false);
        };
        if let Err(err) = session.set_hw_watchpoint(addr, len, kind) {
            println!("set_hw_watchpoint: {err}");
            return Ok(false);
        };
        Ok(true)
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: u32,
        _len: u32,
        _kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let Some(session) = self.session.as_ref() else {
            return Ok(false);
        };
        if let Err(err) = session.clear_hw_watchpoint(addr) {
            println!("clear_hw_watchpoint: {err}");
            return Ok(false);
        };
        Ok(true)
    }
}
