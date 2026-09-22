use core::{
    ffi::{CStr, c_void},
    fmt::{Display, Write},
    mem::zeroed,
    ptr::null_mut,
};

use vitasdk_sys::{
    SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PADDR, SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_IO_NC_RW,
    SceKernelAllocMemBlockKernelOpt, SceKernelModuleInfo, SceKernelProcessContext,
    SceKernelThreadContextInfo, SceKernelThreadInfo, SceUID, ksceKernelAllocMemBlock,
    ksceKernelChangeThreadSuspendStatus, ksceKernelFreeMemBlock, ksceKernelGetMemBlockBase,
    ksceKernelGetProcessStatus, ksceKernelGetThreadIdList, ksceKernelGetThreadInfo,
    ksceKernelProcessGetContext, ksceKernelProcessSwitchContext,
};

use crate::kernel::{
    ffi::{
        ksceGUIDGetUIDVectorByClass, ksceKernelCopyToUserProcTextDomain, ksceKernelCpuResumeIntr,
        ksceKernelCpuSuspendIntr, ksceKernelGetModuleInfo, ksceKernelGetModuleList,
        ksceKernelGetProcessMainThread, ksceKernelGetThreadContextInfo,
        ksceKernelGetUIDProcessClass, ksceKernelL1IcacheInvalidateEntireAllCore,
        ksceKernelResumeProcess, ksceKernelSuspendProcess, ksceKernelSysrootGetProcessTitleId,
    },
    thread::delay_thread,
};
use crate::println;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SceError {
    pub code: i32,
    pub func: &'static str,
}

impl SceError {
    pub const fn new(code: i32, func: &'static str) -> Self {
        Self { code, func }
    }
}

impl Display for SceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} failed: {:#x}", self.func, self.code)
    }
}

#[macro_export]
macro_rules! sce_call {
    ($func:ident ( $($arg:expr),* $(,)? )) => {{
        let ret = unsafe { $func( $($arg),* ) };
        if ret < 0 {
            Err($crate::kernel::utils::SceError::new(ret, stringify!($func)))
        } else {
            Ok(ret)
        }
    }};
}

pub struct StreamWriter<'a> {
    buf: &'a mut [u8],
    skip: usize,
    written: usize,
}

impl<'a> StreamWriter<'a> {
    pub fn new(buf: &'a mut [u8], skip: usize) -> Self {
        Self {
            buf,
            skip,
            written: 0,
        }
    }

    pub fn written(&self) -> usize {
        self.written
    }

    pub fn into_cstr(self) -> Result<&'a CStr, CStrError> {
        if self.written < self.buf.len() {
            self.buf[self.written] = 0;
            CStr::from_bytes_with_nul(&self.buf[..=self.written]).map_err(|_| CStrError::InvalidNul)
        } else {
            Err(CStrError::BufferTooSmall)
        }
    }
}

impl<'a> Write for StreamWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &byte in s.as_bytes() {
            if self.skip > 0 {
                self.skip -= 1;
                continue;
            }
            match self.buf.get_mut(self.written) {
                Some(slot) => {
                    *slot = byte;
                    self.written += 1;
                }
                None => return Err(core::fmt::Error),
            }
        }
        Ok(())
    }
}

pub struct ArgvWriter {
    buf: [u8; 32],
    offset: usize,
}

impl ArgvWriter {
    pub fn new() -> Self {
        Self {
            buf: [0u8; 32],
            offset: 0,
        }
    }

    fn append(&mut self, data: &[u8]) -> bool {
        if self.offset + data.len() >= self.buf.len() {
            return false;
        }
        self.buf[self.offset..self.offset + data.len()].copy_from_slice(data);
        self.offset += data.len() + 1;
        true
    }

    pub fn add(&mut self, name: &str, value: &str) -> bool {
        let name = name.as_bytes();
        let value = value.as_bytes();
        if !self.append(name) {
            return false;
        }
        if !self.append(value) {
            return false;
        }
        return true;
    }

    pub fn to_slice(&self) -> &[u8] {
        &self.buf[..self.offset]
    }
}

#[derive(Debug)]
pub enum CStrError {
    BufferTooSmall,
    InvalidNul,
}

pub fn get_process_ids() -> Result<impl Iterator<Item = SceUID>, SceError> {
    let proc_class = unsafe { ksceKernelGetUIDProcessClass() };
    let mut proc_uids = [0i32; 16];
    let mut proc_num: u32 = 0;
    sce_call!(ksceGUIDGetUIDVectorByClass(
        proc_class,
        8,
        proc_uids.as_mut_ptr(),
        proc_uids.len() as _,
        &mut proc_num as _
    ))?;
    Ok(proc_uids.into_iter().take(proc_num as usize))
}

pub fn get_thread_ids(pid: SceUID) -> Result<impl Iterator<Item = SceUID>, SceError> {
    let mut ids = [0i32; 64];
    let mut copy_count: i32 = 0;
    sce_call!(ksceKernelGetThreadIdList(
        pid,
        ids.as_mut_ptr(),
        ids.len() as _,
        &mut copy_count
    ))?;
    assert!((copy_count as usize) < ids.len());
    Ok(ids.into_iter().take(copy_count as usize))
}

pub fn get_module_ids(pid: SceUID) -> Result<impl Iterator<Item = SceUID>, SceError> {
    let mut modids = [0i32; 64];
    let mut modidnum: u32 = modids.len() as u32;
    sce_call!(ksceKernelGetModuleList(
        pid,
        0x7fffffff,
        1,
        modids.as_mut_ptr(),
        &raw mut modidnum
    ))?;
    Ok(modids.into_iter().take(modidnum as usize))
}

pub fn get_thread_info(tid: SceUID) -> Result<SceKernelThreadInfo, SceError> {
    let mut info: SceKernelThreadInfo = unsafe { core::mem::zeroed() };
    info.size = size_of::<SceKernelThreadInfo>() as _;
    sce_call!(ksceKernelGetThreadInfo(tid, &mut info))?;
    Ok(info)
}

pub fn get_module_info(pid: SceUID, modid: SceUID) -> Result<SceKernelModuleInfo, SceError> {
    let mut info: SceKernelModuleInfo = unsafe { core::mem::zeroed() };
    info.size = size_of::<SceKernelModuleInfo>() as _;
    sce_call!(ksceKernelGetModuleInfo(pid, modid, &mut info))?;
    Ok(info)
}

pub fn get_process_status(pid: SceUID) -> Result<u32, SceError> {
    let mut status: i32 = 0;
    sce_call!(ksceKernelGetProcessStatus(pid, &mut status))?;
    Ok(status as u32)
}

pub fn get_thread_context_info() -> (SceUID, SceUID) {
    let mut thread_ctx: SceKernelThreadContextInfo = unsafe { zeroed() };
    let _ = unsafe { ksceKernelGetThreadContextInfo(&mut thread_ctx) };
    (thread_ctx.process_id, thread_ctx.thread_id)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TitleId([u8; 16]);

impl TitleId {
    pub fn new() -> Self {
        Self([0u8; 16])
    }
    pub fn as_str(&self) -> &str {
        let len = self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len());
        core::str::from_utf8(&self.0[..len]).unwrap_or("")
    }
}

impl PartialEq<str> for TitleId {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl From<&CStr> for TitleId {
    fn from(value: &CStr) -> Self {
        let mut title_id = [0u8; 16];
        let bytes = value.to_bytes();
        let len = bytes.len().min(title_id.len());
        title_id[..len].copy_from_slice(&bytes[..len]);
        Self(title_id)
    }
}

impl Display for TitleId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn get_process_titleid(pid: SceUID) -> Option<TitleId> {
    if pid == 0x10005 {
        return Some(c"kernel".into());
    }
    let mut titleid = TitleId::new();
    match sce_call!(ksceKernelSysrootGetProcessTitleId(
        pid,
        titleid.0.as_mut_ptr() as _,
        titleid.0.len() as _
    )) {
        Err(_) => None,
        Ok(_) => Some(titleid),
    }
}

pub const PROCESS_HALT_STATUS: i32 = 0x1C;
pub const PROCESS_STATUS_SUSPENDED: u32 = 0x10;

pub fn halt_process(pid: SceUID) -> Result<SceUID, SceError> {
    let status = get_process_status(pid)?;
    if status & PROCESS_STATUS_SUSPENDED == 0 {
        sce_call!(ksceKernelSuspendProcess(pid, PROCESS_HALT_STATUS))?;
        let mut waited = 0;
        while waited < 1000 {
            let s = get_process_status(pid)?;
            if s & PROCESS_STATUS_SUSPENDED != 0 {
                break;
            }
            delay_thread(1000);
            waited += 1;
        }
    }
    sce_call!(ksceKernelGetProcessMainThread(pid))
}

pub fn resume_process(pid: SceUID) -> Result<(), SceError> {
    let status = get_process_status(pid)?;
    if status & PROCESS_STATUS_SUSPENDED == 0 {
        return Ok(());
    }
    for tid in get_thread_ids(pid)? {
        if let Err(err) = sce_call!(ksceKernelChangeThreadSuspendStatus(tid, 2)) {
            println!("{err} tid={tid}");
        }
    }
    sce_call!(ksceKernelResumeProcess(pid))?;
    Ok(())
}

pub fn map_paddr(name: &CStr, paddr: u32, size: usize) -> Result<(SceUID, *mut c_void), SceError> {
    let mut opt = SceKernelAllocMemBlockKernelOpt {
        size: size_of::<SceKernelAllocMemBlockKernelOpt>() as u32,
        attr: SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PADDR,
        paddr: paddr,
        ..unsafe { zeroed() }
    };
    let uid = sce_call!(ksceKernelAllocMemBlock(
        name.as_ptr() as _,
        SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_IO_NC_RW,
        size as u32,
        &mut opt
    ))?;
    let mut base: *mut c_void = null_mut();
    sce_call!(ksceKernelGetMemBlockBase(uid, &mut base))?;
    Ok((uid, base))
}

pub fn phys_read32(addr: u32) -> Result<u32, SceError> {
    let (uid, base) = map_paddr(c"tmp", addr & !0xfff, 0x1000)?;
    let value = unsafe {
        base.byte_add((addr & 0xfff) as usize)
            .cast::<u32>()
            .read_volatile()
    };
    sce_call!(ksceKernelFreeMemBlock(uid))?;
    Ok(value)
}

pub fn phys_write32(addr: u32, value: u32) -> Result<(), SceError> {
    let (uid, base) = map_paddr(c"tmp", addr & !0xfff, 0x1000)?;
    unsafe {
        base.byte_add((addr & 0xfff) as usize)
            .cast::<u32>()
            .write_volatile(value)
    };
    sce_call!(ksceKernelFreeMemBlock(uid))?;
    Ok(())
}

pub fn name_to_str(name: &[i8]) -> &str {
    let name_len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    unsafe {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(name.as_ptr() as _, name_len))
    }
}

pub fn write_user_text(pid: SceUID, dst: u32, buf: &[u8]) -> Result<(), SceError> {
    sce_call!(ksceKernelCopyToUserProcTextDomain(
        pid,
        dst as _,
        buf.as_ptr() as _,
        buf.len() as _
    ))?;

    let intr = unsafe { ksceKernelCpuSuspendIntr() };
    let mut proc_ctx: *mut SceKernelProcessContext = null_mut();
    sce_call!(ksceKernelProcessGetContext(pid, &raw mut proc_ctx))?;
    let mut prev_context: SceKernelProcessContext = unsafe { zeroed() };
    sce_call!(ksceKernelProcessSwitchContext(
        proc_ctx,
        &raw mut prev_context
    ))?;

    unsafe { ksceKernelL1IcacheInvalidateEntireAllCore() };

    sce_call!(ksceKernelProcessSwitchContext(
        &mut prev_context,
        null_mut()
    ))?;
    unsafe { ksceKernelCpuResumeIntr(intr) };
    Ok(())
}
