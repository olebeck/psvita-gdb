use core::{ffi::CStr, str::SplitAsciiWhitespace};

use gdbstub::target::ext::monitor_cmd::{ConsoleOutput, MonitorCmd};
use vitasdk_sys::{SceKernelProcessInfo, SceUID, ksceKernelGetProcessInfo};

use crate::{
    gdb::target::VitaTarget,
    kernel::{
        ffi::{ksceGUIDGetUIDVectorByClass, ksceKernelGetUIDMemBlockClass},
        utils::{
            SceError, get_memblock_ids, get_memblock_info, get_module_ids, get_module_info,
            get_process_ids, get_process_status, get_process_titleid, get_thread_ids,
            get_thread_info, name_to_str, phys_read32, phys_write32,
        },
    },
    mep::{mep_read32, mep_write32},
    sce_call,
};

fn parse_num(target: &str) -> Option<u32> {
    let target = target.trim();
    if let Some(hex) = target
        .strip_prefix("0x")
        .or_else(|| target.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        target.parse::<u32>().ok()
    }
}

fn resolve_pid_or_titleid(target: &str) -> Option<SceUID> {
    if let Some(pid) = parse_num(target) {
        Some(pid as SceUID)
    } else {
        get_process_ids().map_or_default(|mut pids| {
            pids.find(|pid| get_process_titleid(*pid).is_some_and(|t| t == target))
        })
    }
}

impl MonitorCmd for VitaTarget {
    fn handle_monitor_cmd(
        &mut self,
        cmd: &[u8],
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        let Ok(cmd) = core::str::from_utf8(cmd) else {
            gdbstub::outputln!(out, "command must be valid UTF-8");
            return Ok(());
        };
        let mut args = cmd.split_ascii_whitespace();
        let Some(cmd) = args.next() else {
            return self.cmd_help(&mut args, out);
        };

        match cmd {
            "dump" => self.cmd_dump(&mut args, out),
            "ps" => self.cmd_ls_process(out),
            "ls" => self.cmd_ls(&mut args, out),
            "info" => self.cmd_info(&mut args, out),
            "peek" => self.cmd_peek(&mut args, out),
            "poke" => self.cmd_poke(&mut args, out),
            _ => self.cmd_help(&mut args, out),
        }
    }
}

impl VitaTarget {
    fn cmd_help(
        &mut self,
        _args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        gdbstub::outputln!(out, "dump                     Dump gdb session internals");
        gdbstub::outputln!(out, "ps                       Print a list of processes");
        gdbstub::outputln!(out, "ls process               Print a list of processes");
        gdbstub::outputln!(out, "ls thread <pid|titleid>  Print a list of threads");
        gdbstub::outputln!(out, "ls module <pid|titleid>  Print a list of modules");
        gdbstub::outputln!(out, "ls memblock              Print a list of memblocks");
        gdbstub::outputln!(out, "info process [pid|titleid] Print process details");
        gdbstub::outputln!(out, "info thread <tid>        Print thread details");
        gdbstub::outputln!(out, "info memblock <uid>      Print memory block details");
        gdbstub::outputln!(out, "peek <addr> [S]          Peek a physical address");
        gdbstub::outputln!(out, "poke <addr> <value> [S]  Poke a physical address");
        Ok(())
    }

    fn cmd_dump(
        &mut self,
        _args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        let Some(session) = self.session.as_ref() else {
            gdbstub::outputln!(out, "no session");
            return Ok(());
        };
        let d = session.dump_state();

        gdbstub::output!(out, "pid  ");
        if let Some(pid) = d.pid {
            gdbstub::outputln!(out, "0x{pid:x}");
        } else {
            gdbstub::outputln!(out, "(none)");
        }
        gdbstub::outputln!(out, "hw breakpoints  {}/6", d.hw_breakpoints.len());
        for (i, a) in d.hw_breakpoints.iter().enumerate() {
            gdbstub::outputln!(out, "  [{i}] 0x{a:x}");
        }
        gdbstub::outputln!(out, "hw watchpoints  {}/3", d.hw_watchpoints.len());
        for (i, a) in d.hw_watchpoints.iter().enumerate() {
            gdbstub::outputln!(out, "  [{i}] 0x{a:x}");
        }
        gdbstub::outputln!(out, "sw breakpoints  {}/16", d.sw_breakpoints.len());
        for (i, a) in d.sw_breakpoints.iter().enumerate() {
            gdbstub::outputln!(out, "  [{i}] 0x{a:x}");
        }
        Ok(())
    }

    fn cmd_ls(
        &mut self,
        args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        match args.next() {
            Some("process") => self.cmd_ls_process(out),
            Some("thread") => self.cmd_ls_thread(args, out),
            Some("module") => self.cmd_ls_module(args, out),
            Some("memblock") => self.cmd_ls_memblock(out),
            _ => {
                gdbstub::outputln!(out, "usage: ls <process | thread | module | memblock>");
                Ok(())
            }
        }
    }

    fn cmd_ls_process(&mut self, mut out: ConsoleOutput<'_>) -> Result<(), SceError> {
        let pids = match get_process_ids() {
            Err(err) => {
                gdbstub::outputln!(out, "ls process: lookup {err}");
                return Ok(());
            }
            Ok(pids) => pids,
        };
        for pid in pids {
            gdbstub::output!(out, "0x{pid:x}");
            if let Some(titleid) = get_process_titleid(pid) {
                gdbstub::output!(out, "  {titleid}");
            } else {
                gdbstub::output!(out, "  unknown");
            }
            match get_process_status(pid) {
                Ok(status) => {
                    gdbstub::output!(out, "  status 0x{status:x}");
                }
                Err(err) => {
                    gdbstub::output!(out, "  status {err}");
                }
            }
            gdbstub::outputln!(out, "");
        }
        Ok(())
    }

    fn cmd_ls_memblock(&mut self, mut out: ConsoleOutput<'_>) -> Result<(), SceError> {
        let uids = match get_memblock_ids() {
            Err(err) => {
                gdbstub::outputln!(out, "ls memblock: lookup {err}");
                return Ok(());
            }
            Ok(pids) => pids,
        };
        for uid in uids {
            let info = match get_memblock_info(uid) {
                Ok(info) => info,
                Err(err) => {
                    gdbstub::outputln!(out, "0x{uid:<9x} (get info {err})");
                    continue;
                }
            };
            gdbstub::output!(out, "0x{uid:<9x} ");
            if info.core_info.name.is_null() {
                gdbstub::output!(out, "<unnamed>");
            } else {
                let name = unsafe { CStr::from_ptr(info.core_info.name) };
                gdbstub::output!(out, "{name:<32?}");
            }
            gdbstub::outputln!(
                out,
                " type=0x{:x} base=0x{:x} size=0x{:x}",
                info.core_info.type_,
                info.core_info.mapped_base as u32,
                info.core_info.mapped_size
            );
        }
        Ok(())
    }

    fn pid_arg(&self, arg: Option<&str>) -> Option<SceUID> {
        if let Some(target) = arg {
            return resolve_pid_or_titleid(target);
        }
        self.pid()
    }

    fn cmd_ls_thread(
        &mut self,
        args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        let Some(pid) = self.pid_arg(args.next()) else {
            gdbstub::outputln!(out, "usage: ls thread <pid|titleid>");
            gdbstub::outputln!(out, "ls thread: argument is not a pid or titleid");
            return Ok(());
        };

        let thread_ids = match get_thread_ids(pid) {
            Ok(tids) => tids,
            Err(err) => {
                gdbstub::outputln!(out, "ls thread: pid=0x{pid:x} {err}");
                return Ok(());
            }
        };
        for tid in thread_ids {
            let info = match get_thread_info(tid) {
                Ok(info) => info,
                Err(err) => {
                    gdbstub::outputln!(out, "tid=0x{tid:x}  (get info {err})");
                    continue;
                }
            };
            let name = name_to_str(info.name.as_slice());
            gdbstub::output!(out, "  0x{tid:<9x} {:<32}", name);
            gdbstub::outputln!(
                out,
                "prio {:<3} status 0x{:x}",
                info.initPriority,
                info.status
            );
        }
        Ok(())
    }

    fn cmd_ls_module(
        &mut self,
        args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        let Some(pid) = self.pid_arg(args.next()) else {
            gdbstub::outputln!(out, "usage: ls module <pid|titleid>");
            gdbstub::outputln!(out, "ls module: argument is not a pid or titleid");
            return Ok(());
        };

        let module_ids = match get_module_ids(pid) {
            Ok(modids) => modids,
            Err(err) => {
                gdbstub::outputln!(out, "ls module: pid={pid} {err}");
                return Ok(());
            }
        };

        for modid in module_ids {
            let info = match get_module_info(pid, modid) {
                Ok(info) => info,
                Err(err) => {
                    gdbstub::outputln!(out, "modid=0x{modid:x}  (get info {err})");
                    continue;
                }
            };
            let name = name_to_str(info.module_name.as_slice());
            let path = name_to_str(info.path.as_slice());
            gdbstub::output!(out, "0x{modid:<9x} {:<32}", name);
            gdbstub::outputln!(out, " state=0x{:x} {}", info.state, path);
            if false {
                for seg in &info.segments {
                    if seg.size == 0 {
                        continue;
                    }
                    gdbstub::outputln!(
                        out,
                        "  vaddr=0x{:x} size={} perms={}",
                        seg.vaddr as u32,
                        seg.memsz,
                        seg.perms
                    );
                }
                gdbstub::outputln!(out, "");
            }
        }
        Ok(())
    }

    fn cmd_info(
        &mut self,
        args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        match args.next() {
            Some("process") => self.cmd_info_process(args, out),
            Some("thread") => self.cmd_info_thread(args, out),
            Some("memblock") => self.cmd_info_memblock(args, out),
            _ => {
                gdbstub::outputln!(out, "usage: info <process|thread|memblock> [id]");
                Ok(())
            }
        }
    }

    fn cmd_info_process(
        &mut self,
        args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        let Some(pid) = self.pid_arg(args.next()) else {
            gdbstub::outputln!(out, "usage: info process [pid|titleid]");
            gdbstub::outputln!(out, "info process: argument is not a pid or titleid");
            return Ok(());
        };

        let mut info: SceKernelProcessInfo = unsafe { core::mem::zeroed() };
        info.size = size_of::<SceKernelProcessInfo>() as _;
        if let Err(err) = sce_call!(ksceKernelGetProcessInfo(pid, &mut info)) {
            gdbstub::outputln!(out, "info process: pid=0x{pid:x} {err}",);
            return Ok(());
        }

        gdbstub::outputln!(out, "pid       0x{:x}", info.pid);
        gdbstub::outputln!(out, "ppid      0x{:x}", info.ppid);
        if let Some(titleid) = get_process_titleid(pid) {
            gdbstub::outputln!(out, "titleid   {titleid}");
        }
        match get_process_status(pid) {
            Ok(status) => gdbstub::outputln!(out, "status    0x{status:x}"),
            Err(err) => gdbstub::outputln!(out, "status    {err}"),
        }
        Ok(())
    }

    fn cmd_info_thread(
        &mut self,
        args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        let Some(tid) = args.next().and_then(parse_num).map(|tid| tid as SceUID) else {
            gdbstub::outputln!(out, "usage: info thread <tid>");
            return Ok(());
        };
        let info = match get_thread_info(tid) {
            Ok(info) => info,
            Err(err) => {
                gdbstub::outputln!(out, "info thread: tid=0x{tid:x} {err}");
                return Ok(());
            }
        };

        gdbstub::outputln!(out, "tid       0x{tid:x}");
        gdbstub::outputln!(out, "pid       0x{:x}", info.processId);
        gdbstub::outputln!(out, "name      {}", name_to_str(info.name.as_slice()));
        gdbstub::outputln!(out, "status    0x{:x}", info.status);
        gdbstub::outputln!(out, "attr      0x{:x}", info.attr);
        match info.entry {
            Some(entry) => gdbstub::outputln!(out, "entry     0x{:x}", entry as usize as u32),
            None => gdbstub::outputln!(out, "entry     <none>"),
        }
        gdbstub::outputln!(out, "stack      0x{:x}", info.stack as u32);
        gdbstub::outputln!(out, "stack size 0x{:x}", info.stackSize);
        gdbstub::outputln!(
            out,
            "priority  initial={} current={}",
            info.initPriority,
            info.currentPriority
        );
        gdbstub::outputln!(
            out,
            "cpu       current={} affinity=0x{:x}",
            info.currentCpuId,
            info.currentCpuAffinityMask
        );
        gdbstub::outputln!(
            out,
            "wait      type=0x{:x} id={}",
            info.waitType,
            info.waitId
        );
        gdbstub::outputln!(out, "exit status {}", info.exitStatus);
        Ok(())
    }

    fn cmd_info_memblock(
        &mut self,
        args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        let Some(uid) = args.next().and_then(parse_num).map(|uid| uid as SceUID) else {
            gdbstub::outputln!(out, "usage: info memblock <uid>");
            return Ok(());
        };
        let info = match get_memblock_info(uid) {
            Ok(info) => info,
            Err(err) => {
                gdbstub::outputln!(out, "info memblock: uid=0x{uid:x} {err}");
                return Ok(());
            }
        };

        gdbstub::outputln!(out, "uid        0x{uid:x}");
        if info.core_info.name.is_null() {
            gdbstub::outputln!(out, "name       <unnamed>");
        } else {
            let name = unsafe { CStr::from_ptr(info.core_info.name) };
            gdbstub::outputln!(out, "name       {name:<32?}",);
        }
        gdbstub::outputln!(out, "type       0x{:x}", info.core_info.type_);
        gdbstub::outputln!(
            out,
            "mapping    base=0x{:x} size=0x{:x} allocated=0x{:x}",
            info.core_info.mapped_base as u32,
            info.core_info.mapped_size,
            info.core_info.alloc_map_size
        );
        gdbstub::outputln!(out, "partition  {}", info.core_info.partition_guid);
        for i in 0..(info.physical_range_count_written as usize).min(info.physical_addresses.len())
        {
            gdbstub::outputln!(
                out,
                "physical[{}] base=0x{:x} size=0x{:x}",
                i,
                info.physical_addresses[i] as u32,
                info.physical_sizes[i]
            );
        }
        Ok(())
    }

    fn cmd_peek(
        &mut self,
        args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        let Some(addr) = args.next() else {
            gdbstub::outputln!(out, "usage: peek <addr> [S]");
            return Ok(());
        };
        let Some(addr) = parse_num(addr) else {
            gdbstub::outputln!(out, "addr not valid");
            return Ok(());
        };

        let secure = match args.next() {
            None => false,
            Some("S") => true,
            Some(_) => {
                gdbstub::outputln!(out, "usage: peek <addr> [S]");
                return Ok(());
            }
        };

        let value = if secure {
            mep_read32(addr)?
        } else {
            phys_read32(addr)?
        };
        gdbstub::outputln!(out, "{value:x}");
        Ok(())
    }

    fn cmd_poke(
        &mut self,
        args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        let (Some(dst), Some(value)) = (args.next(), args.next()) else {
            gdbstub::outputln!(out, "usage: poke <dst> <value> [S]");
            return Ok(());
        };
        let (Some(dst), Some(value)) = (parse_num(dst), parse_num(value)) else {
            gdbstub::outputln!(out, "dst or value not valid");
            return Ok(());
        };

        let secure = match args.next() {
            None => false,
            Some("S") => true,
            Some(_) => {
                gdbstub::outputln!(out, "usage: poke <addr> <value> [S]");
                return Ok(());
            }
        };

        if secure {
            mep_write32(dst, value)?;
        } else {
            phys_write32(dst, value)?;
        }
        gdbstub::outputln!(out, "OK");
        Ok(())
    }
}
