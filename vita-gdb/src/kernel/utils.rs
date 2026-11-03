use core::{
    ffi::{CStr, c_void},
    fmt::{Debug, Display, Write},
    mem::zeroed,
    ptr::null_mut,
};

use vitasdk_sys::{
    SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PADDR, SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_IO_NC_RW, SceClass,
    SceKernelAllocMemBlockKernelOpt, SceKernelIntrStatus, SceKernelMemBlockInfoEx,
    SceKernelModuleInfo, SceKernelProcessContext, SceKernelThreadContextInfo, SceKernelThreadInfo,
    SceUID, ksceKernelAllocMemBlock, ksceKernelChangeThreadSuspendStatus, ksceKernelFreeMemBlock,
    ksceKernelGetMemBlockBase, ksceKernelGetMemBlockInfo, ksceKernelGetProcessStatus,
    ksceKernelGetThreadIdList, ksceKernelGetThreadInfo, ksceKernelProcessGetContext,
    ksceKernelProcessSwitchContext,
};

use crate::kernel::{
    ffi::{
        ksceGUIDGetUIDVectorByClass, ksceKernelCopyToUserTextDomain, ksceKernelCpuResumeIntr,
        ksceKernelCpuSuspendIntr, ksceKernelGetModuleInfo, ksceKernelGetModuleList,
        ksceKernelGetProcessMainThread, ksceKernelGetThreadContextInfo,
        ksceKernelGetUIDMemBlockClass, ksceKernelGetUIDProcessClass,
        ksceKernelL1IcacheInvalidateEntireAllCore, ksceKernelResumeProcess,
        ksceKernelSuspendProcess, ksceKernelSysrootGetProcessTitleId,
    },
    thread::delay_thread,
};
use crate::println;

#[derive(Clone, Copy, PartialEq, Eq)]
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

impl Debug for SceError {
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

    pub fn into_cstr(self) -> Option<&'a CStr> {
        if self.written >= self.buf.len() {
            return None;
        }
        self.buf[self.written] = 0;
        CStr::from_bytes_with_nul(&self.buf[..=self.written]).ok()
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
    buf: [u8; 256],
    offset: usize,
}

impl ArgvWriter {
    pub fn new() -> Self {
        Self {
            buf: [0u8; 256],
            offset: 0,
        }
    }

    fn append(&mut self, data: &[u8]) -> bool {
        if self.offset + data.len() + 3 > self.buf.len() {
            return false;
        }
        self.buf[self.offset..self.offset + data.len()].copy_from_slice(data);
        self.offset += data.len() + 1;
        true
    }

    pub fn add(&mut self, name: &str, value: &str) -> bool {
        self.append(name.as_bytes()) && self.append(value.as_bytes())
    }

    pub fn add_arg(&mut self, arg: &[u8]) -> bool {
        self.append(arg)
    }

    pub fn to_slice(&self) -> &[u8] {
        &self.buf[..(self.offset + 1).min(self.buf.len())]
    }
}

fn get_class_uid_vec<const N: usize>(
    sce_class: *mut SceClass,
) -> Result<impl Iterator<Item = SceUID>, SceError> {
    let mut uids = [0; N];
    let mut count = 0;
    sce_call!(ksceGUIDGetUIDVectorByClass(
        sce_class,
        8,
        uids.as_mut_ptr(),
        uids.len() as u32,
        &mut count
    ))?;
    Ok(uids.into_iter().take(count as usize))
}

pub fn get_process_ids() -> Result<impl Iterator<Item = SceUID>, SceError> {
    get_class_uid_vec::<16>(unsafe { ksceKernelGetUIDProcessClass() })
}

pub fn get_memblock_ids() -> Result<impl Iterator<Item = SceUID>, SceError> {
    get_class_uid_vec::<128>(unsafe { ksceKernelGetUIDMemBlockClass() })
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
    let count = copy_count.max(0) as usize;
    Ok(ids.into_iter().take(count.min(ids.len())))
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

pub fn get_memblock_info(uid: SceUID) -> Result<SceKernelMemBlockInfoEx, SceError> {
    let mut info: SceKernelMemBlockInfoEx = unsafe { core::mem::zeroed() };
    info.size = core::mem::size_of::<SceKernelMemBlockInfoEx>() as _;
    sce_call!(ksceKernelGetMemBlockInfo(uid, 7, &mut info))?;
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
    const fn new_static(value: &str) -> Self {
        if value.len() > 16 {
            panic!("TitleId must be at most 16 bytes");
        }
        let mut buf = [0u8; 16];
        let bytes = value.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            buf[i] = bytes[i];
            i += 1;
        }
        Self(buf)
    }
    pub fn as_str(&self) -> &str {
        let len = self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len());
        core::str::from_utf8(&self.0[..len]).unwrap_or("")
    }
}

impl PartialEq<&str> for TitleId {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl Display for TitleId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn get_process_titleid(pid: SceUID) -> Option<TitleId> {
    if pid == 0x10005 {
        return Some(TitleId::new_static("kernel"));
    }
    let mut buf = TitleId::new();
    sce_call!(ksceKernelSysrootGetProcessTitleId(
        pid,
        buf.0.as_mut_ptr() as _,
        buf.0.len() as _
    ))
    .ok();
    Some(buf).filter(|t| !t.as_str().is_empty())
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

struct ProcessContextGuard {
    prev: SceKernelProcessContext,
    intr: SceKernelIntrStatus,
}

impl ProcessContextGuard {
    fn enter(pid: SceUID) -> Result<Self, SceError> {
        let mut proc_ctx: *mut SceKernelProcessContext = null_mut();
        sce_call!(ksceKernelProcessGetContext(pid, &raw mut proc_ctx))?;
        let intr = unsafe { ksceKernelCpuSuspendIntr() };
        let mut prev = unsafe { zeroed() };
        sce_call!(ksceKernelProcessSwitchContext(proc_ctx, &raw mut prev)).inspect_err(|_| {
            unsafe { ksceKernelCpuResumeIntr(intr) };
        })?;
        Ok(Self { prev, intr })
    }
}

impl Drop for ProcessContextGuard {
    fn drop(&mut self) {
        let _ = unsafe { ksceKernelProcessSwitchContext(&mut self.prev, null_mut()) };
        let _ = unsafe { ksceKernelCpuResumeIntr(self.intr) };
    }
}

pub fn write_user_text(pid: SceUID, dst: u32, buf: &[u8]) -> Result<(), SceError> {
    let ctx = ProcessContextGuard::enter(pid)?;
    sce_call!(ksceKernelCopyToUserTextDomain(
        dst as *mut c_void,
        buf.as_ptr() as *const c_void,
        buf.len()
    ))?;
    unsafe { ksceKernelL1IcacheInvalidateEntireAllCore() };
    drop(ctx);
    Ok(())
}
