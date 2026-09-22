use core::{
    ffi::{CStr, c_void},
    marker::PhantomData,
    mem::ManuallyDrop,
    ptr::{null, null_mut},
};

use vitasdk_sys::{
    SCE_KERNEL_THREAD_CPU_AFFINITY_MASK_DEFAULT, SceKernelThreadEntry, SceUID,
    ksceKernelCreateThread, ksceKernelDelayThread, ksceKernelDeleteThread,
    ksceKernelExitDeleteThread, ksceKernelStartThread, ksceKernelWaitThreadEnd,
};

use crate::{kernel::utils::SceError, sce_call};

fn start_thread<T>(thid: SceUID, arg: T) -> Result<(), SceError> {
    let mut arg = ManuallyDrop::new(arg);
    if let Err(err) = sce_call!(ksceKernelStartThread(
        thid,
        core::mem::size_of::<T>() as u32,
        (&raw mut arg) as *mut T as *mut c_void
    )) {
        unsafe { ManuallyDrop::drop(&mut arg) };
        return Err(err);
    };
    Ok(())
}

fn create_thread(
    name: &CStr,
    entry: SceKernelThreadEntry,
    priority: u32,
    stack_size: usize,
) -> Result<SceUID, SceError> {
    sce_call!(ksceKernelCreateThread(
        name.as_ptr(),
        entry,
        priority as i32,
        stack_size as u32,
        0x0,
        SCE_KERNEL_THREAD_CPU_AFFINITY_MASK_DEFAULT as _,
        null(),
    ))
}

struct ThreadArg<T> {
    entry: fn(T),
    arg: T,
}

unsafe extern "C" fn thread_trampoline<T>(_: u32, argv: *mut c_void) -> i32 {
    let ThreadArg { entry, arg } = unsafe { (argv as *const ThreadArg<T>).read() };
    entry(arg);
    0
}

unsafe extern "C" fn thread_trampoline_delete<T>(_: u32, argv: *mut c_void) -> i32 {
    let ThreadArg { entry, arg } = unsafe { (argv as *const ThreadArg<T>).read() };
    entry(arg);
    unsafe { ksceKernelExitDeleteThread(0) };
    0
}

pub struct JoinableThread<T> {
    thid: SceUID,
    _marker: PhantomData<fn(T)>,
}

impl<T: 'static> JoinableThread<T> {
    pub fn create(name: &CStr, priority: u32, stack_size: usize) -> Result<Self, SceError> {
        let thid = create_thread(name, Some(thread_trampoline::<T>), priority, stack_size)?;
        Ok(Self {
            thid,
            _marker: PhantomData,
        })
    }

    pub fn start(&self, entry: fn(T), arg: T) -> Result<(), SceError> {
        start_thread(self.thid, ThreadArg { entry: entry, arg })
    }

    pub fn join(self) -> Result<i32, SceError> {
        let mut status = 0;
        sce_call!(ksceKernelWaitThreadEnd(self.thid, &mut status, null_mut()))?;
        sce_call!(ksceKernelDeleteThread(self.thid))?;
        Ok(status)
    }
}

pub struct DetachedThread<T> {
    thid: SceUID,
    _marker: PhantomData<fn(T)>,
}

impl<T: 'static> DetachedThread<T> {
    pub fn create(name: &CStr, priority: u32, stack_size: usize) -> Result<Self, SceError> {
        let thid = create_thread(
            name,
            Some(thread_trampoline_delete::<T>),
            priority,
            stack_size,
        )?;
        Ok(Self {
            thid,
            _marker: PhantomData,
        })
    }

    pub fn start(self, entry: fn(T), arg: T) -> Result<(), SceError> {
        let result = start_thread(self.thid, ThreadArg { entry: entry, arg });
        if result.is_err() {
            let _ = unsafe { ksceKernelDeleteThread(self.thid) };
        }
        result
    }
}

pub fn delay_thread(delay: u32) {
    unsafe { ksceKernelDelayThread(delay) };
}
