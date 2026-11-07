use core::{
    ffi::CStr,
    fmt::{Display, Write},
    mem::zeroed,
    ptr::null_mut,
};
use gdbstub::{
    common::{Pid, Tid},
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
            section_offsets::{Offsets, SectionOffsets, SectionOffsetsOps},
            threads::{Threads, ThreadsOps},
        },
    },
};
use gdbstub_arch::arm::ArmBreakpointKind;
use heapless::Vec;
use vitasdk_sys::{SceAppMgrLaunchParam, SceUID, ksceAppMgrKillProcess, ksceAppMgrLaunchAppByPath};

use crate::{
    cp14::is_debug_enabled,
    gdb::{armv7::Armv7, sessions::GdbSession},
    kernel::{
        event_flag::EventFlagRef,
        ffi::ksceKernelGetModuleIdByPid,
        thread::delay_thread,
        utils::{
            ArgvWriter, SceError, StreamWriter, get_module_ids, get_module_info, get_process_ids,
            get_process_status, get_thread_ids, get_thread_info, halt_process, name_to_str,
            resume_process, str_to_buf,
        },
    },
    println, sce_call,
};

const FAKE_PID: Pid = const { Pid::new(1).unwrap() };

fn is_title_id(value: &str) -> bool {
    value.len() == 9
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn wait_for_process(pid: SceUID) -> Result<(), SceError> {
    let mut last_err = SceError::new(-1, "get_process_status");
    for _ in 0..1000 {
        match get_process_status(pid) {
            Ok(status) => {
                if status & 0x10 != 0 {
                    return Ok(());
                }
            }
            Err(err) => last_err = err,
        }
        delay_thread(10_000);
    }
    Err(last_err)
}

pub struct VitaTarget {
    pub(crate) session: Option<GdbSession>,
    pub(crate) evflag: EventFlagRef,
    pub(crate) detached: bool,
    pub(crate) attach_kind: AttachKind,
    pub(crate) step_action: Option<SceUID>,
    pub(crate) continue_actions: Vec<SceUID, 64>,
}

impl VitaTarget {
    pub fn new(evflag: EventFlagRef) -> VitaTarget {
        VitaTarget {
            session: None,
            evflag,
            detached: false,
            attach_kind: AttachKind::Attach,
            step_action: None,
            continue_actions: Vec::new(),
        }
    }

    pub fn pid(&self) -> Option<SceUID> {
        self.session.as_ref().map(|s| s.inner().pid())
    }

    pub fn attach(&mut self, pid: SceUID, kind: AttachKind) -> bool {
        if self.session.is_some() {
            println!("already attached");
            return false;
        }
        let Some(session) = GdbSession::new(self.evflag, pid) else {
            println!("gdb session for pid {pid} already exists or no free slots");
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
            let pid = session.inner().pid();
            let _ = resume_process(pid);
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
    type Tid = Tid;

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error, Self::Tid> {
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

    #[inline(always)]
    fn support_section_offsets(&mut self) -> Option<SectionOffsetsOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_threads(&mut self) -> Option<ThreadsOps<'_, Self>> {
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
        Err(SceError::new(-1, "ExtendedMode::restart"))
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

    fn run(&mut self, filename: Option<&[u8]>, args: Args<'_, '_>) -> TargetResult<Pid, Self> {
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

        let mut path_buf = [0u8; 128];
        let mut writer = StreamWriter::new(&mut path_buf, 0);
        let titleid = if is_title_id(filename) {
            let _ = write!(writer, "ux0:app/{filename}/eboot.bin");
            Some(filename)
        } else {
            let _ = write!(writer, "{filename}");
            None
        };
        let Some(executable_path) = writer.into_cstr() else {
            println!("filename too long");
            return Err(TargetError::NonFatal);
        };

        let mut launch_args = ArgvWriter::new();
        if let Some(titleid) = titleid {
            if !launch_args.add("-titleid", titleid) {
                println!("run: launch arguments too long");
                return Err(TargetError::NonFatal);
            }
        }
        for arg in args {
            if !launch_args.add_arg(arg) {
                println!("run: launch arguments too long");
                return Err(TargetError::NonFatal);
            }
        }
        let launch_args = launch_args.to_slice();

        const SCE_APPMGR_LAUNCH_PARAM_FLAG_DEBUG_SUSPEND: u32 = 0x80000000;

        let pid = sce_call!(ksceAppMgrLaunchAppByPath(
            executable_path.as_ptr(),
            launch_args.as_ptr() as _,
            launch_args.len() as _,
            SCE_APPMGR_LAUNCH_PARAM_FLAG_DEBUG_SUSPEND,
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

        if let Err(err) = wait_for_process(pid) {
            println!("run: process {pid} did not start: {err}");
            self.detach();
            return Err(TargetError::NonFatal);
        }

        let pid = Pid::new(pid as _).ok_or(TargetError::NonFatal)?;
        Ok(pid)
    }
}

impl CurrentActivePid for VitaTarget {
    fn current_active_pid(&mut self) -> Result<Pid, Self::Error> {
        Ok(match self.pid() {
            Some(pid) => unsafe { Pid::new_unchecked(pid as _) },
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

impl Threads for VitaTarget {
    fn get_threads(
        &self,
        offset: u64,
        _length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let Some(pid) = self.pid() else {
            return Ok(0);
        };

        let tids = match get_thread_ids(pid) {
            Ok(tids) => tids,
            Err(err) => {
                println!("{err} pid={pid}");
                return Err(TargetError::NonFatal);
            }
        };

        let mut writer = StreamWriter::new(buf, offset as _);
        let _ = write!(writer, "<?xml version=\"1.0\"?><threads>");
        for tid in tids {
            let info = match get_thread_info(tid) {
                Ok(info) => info,
                Err(err) => {
                    println!("get_thread_info(0x{tid:x}): {err}");
                    continue;
                }
            };
            let Ok(name) = unsafe { CStr::from_ptr(info.name.as_ptr() as _) }.to_str() else {
                continue;
            };
            let core = if info.currentCpuId >= 0 {
                info.currentCpuId
            } else {
                info.lastExecutedCpuId
            };
            let _ = write!(
                writer,
                "<thread id=\"{}\" core=\"{core}\" name=\"{name}\" id_str=\"{name}\"></thread>",
                format_tid(tid as _)
            );
        }
        let _ = write!(writer, "</threads>");
        Ok(writer.written())
    }
}

fn format_tid(tid: usize) -> impl Display {
    struct TidDisplay(usize);
    impl Display for TidDisplay {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{:08x}", self.0)
        }
    }
    TidDisplay(tid)
}

impl SectionOffsets for VitaTarget {
    fn get_section_offsets(
        &mut self,
    ) -> Result<Offsets<<Self::Arch as gdbstub::arch::Arch>::Usize>, Self::Error> {
        let Some(pid) = self.pid() else {
            return Err(SceError::new(-1, "no pid"));
        };

        let modid = match sce_call!(ksceKernelGetModuleIdByPid(pid)) {
            Ok(modid) => modid,
            Err(err) => {
                println!("get_section_offsets: {err}");
                return Err(err);
            }
        };
        let info = match get_module_info(pid, modid) {
            Ok(info) => info,
            Err(err) => {
                println!("get_section_offsets: {err} pid={pid} modid={modid}");
                return Err(err);
            }
        };
        Ok(Offsets::Segments {
            text_seg: info.segments[0].vaddr as _,
            data_seg: Some(info.segments[1].vaddr as _),
        })
    }
}

impl ProcessInfo for VitaTarget {
    #[inline(always)]
    fn process_info(
        &self,
        write_item: &mut dyn FnMut(&ProcessInfoResponse<'_>),
    ) -> Result<(), Self::Error> {
        for pid in get_process_ids()? {
            let pid = unsafe { Pid::new_unchecked(pid as _) };
            write_item(&ProcessInfoResponse::Pid(pid));
        }
        Ok(())
    }
}

impl ExecFile for VitaTarget {
    fn get_exec_file(
        &self,
        pid: Option<Pid>,
        offset: u64,
        _length: usize,
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

        let Some(path) = name_to_str(&info.path) else {
            return Ok(0);
        };
        Ok(str_to_buf(buf, path, offset as _))
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
        match session.set_hw_breakpoint(addr) {
            Ok(ok) => Ok(ok),
            Err(err) => {
                println!("set_hw_breakpoint: {err}");
                Ok(false)
            }
        }
    }

    fn remove_hw_breakpoint(
        &mut self,
        addr: u32,
        _kind: ArmBreakpointKind,
    ) -> TargetResult<bool, Self> {
        let Some(session) = self.session.as_ref() else {
            return Ok(false);
        };
        match session.clear_hw_breakpoint(addr) {
            Ok(ok) => Ok(ok),
            Err(err) => {
                println!("clear_hw_breakpoint: {err}");
                Ok(false)
            }
        }
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
        match session.set_hw_watchpoint(addr, len, kind) {
            Ok(ok) => Ok(ok),
            Err(err) => {
                println!("set_hw_watchpoint: {err}");
                Ok(false)
            }
        }
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
        match session.clear_hw_watchpoint(addr) {
            Ok(ok) => Ok(ok),
            Err(err) => {
                println!("clear_hw_watchpoint: {err}");
                Ok(false)
            }
        }
    }
}
