use core::str::SplitAsciiWhitespace;

use gdbstub::target::ext::monitor_cmd::{ConsoleOutput, MonitorCmd};
use vitasdk_sys::SceUID;

use crate::{
    gdb::target::VitaTarget,
    kernel::utils::{
        SceError, get_module_ids, get_module_info, get_process_ids, get_process_status,
        get_process_titleid, get_thread_ids, get_thread_info, name_to_str, phys_read32,
        phys_write32,
    },
    mep::{mep_read32, mep_write32},
};

fn resolve_pid_or_titleid(target: &str) -> Option<SceUID> {
    target.parse().ok().or_else(|| {
        get_process_ids().map_or_default(|mut pids| {
            pids.find(|pid| get_process_titleid(*pid).is_some_and(|t| t == *target))
        })
    })
}

fn parse_num(s: &str) -> Option<u32> {
    match s.strip_prefix("0x") {
        Some(s) => u32::from_str_radix(s, 16).ok(),
        None => s.parse().ok(),
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
            "nid" => self.cmd_lookup_nid(&mut args, out),
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
            gdbstub::outputln!(out, "{pid}");
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
            _ => {
                gdbstub::outputln!(out, "usage: ls <process|thread|module> [pid]");
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
            gdbstub::output!(out, "{pid}");
            if let Some(titleid) = get_process_titleid(pid) {
                gdbstub::output!(out, "  {titleid}");
            } else {
                gdbstub::output!(out, "  unknown");
            }
            let status = get_process_status(pid)?;
            gdbstub::output!(out, "  status 0x{status:x}");
            gdbstub::outputln!(out, "");
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
                gdbstub::outputln!(out, "ls thread: pid={pid} {err}");
                return Ok(());
            }
        };
        for tid in thread_ids {
            let info = match get_thread_info(tid) {
                Ok(info) => info,
                Err(err) => {
                    gdbstub::outputln!(out, "tid={tid}  (get info {err})");
                    continue;
                }
            };
            let name = name_to_str(info.name.as_slice());
            gdbstub::output!(out, "  {tid:<9} {:<32}", name);
            gdbstub::outputln!(out, "prio {} status 0x{:x}", info.initPriority, info.status);
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
                    gdbstub::outputln!(out, "modid={modid}  (get info {err})");
                    continue;
                }
            };
            let name = name_to_str(info.module_name.as_slice());
            let path = name_to_str(info.path.as_slice());
            gdbstub::output!(out, "{modid:<9} {:<32}", name);
            gdbstub::outputln!(out, " state=0x{:x} path={}", info.state, path);
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
            Some("process") => self.cmd_ls_process(out),
            Some("thread") => self.cmd_ls_thread(args, out),
            _ => {
                gdbstub::outputln!(out, "usage: ls <process|thread> [pid]");
                Ok(())
            }
        }
    }

    fn cmd_lookup_nid(
        &mut self,
        args: &mut SplitAsciiWhitespace<'_>,
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), SceError> {
        let Some(nid_str) = args.next() else {
            gdbstub::outputln!(out, "usage: nid <func_nid>");
            return Ok(());
        };
        let Some(nid) = parse_num(nid_str) else {
            gdbstub::outputln!(out, "nid: '{nid_str}' is not a valid");
            return Ok(());
        };

        let addr = self.lookup_nid(nid);
        match addr {
            Some(addr) => gdbstub::outputln!(out, "0x{addr:x}"),
            None => gdbstub::outputln!(out, "not found"),
        }
        Ok(())
    }

    fn lookup_nid(&mut self, _nid: u32) -> Option<u32> {
        // TODO
        None
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
