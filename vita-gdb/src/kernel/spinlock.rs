use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
};

use vitasdk_sys::{
    SceKernelIntrStatus, SceKernelSpinlock, ksceKernelSpinlockLowLockCpuSuspendIntr,
    ksceKernelSpinlockLowUnlockCpuResumeIntr,
};

pub struct Spinlock<T> {
    lock: UnsafeCell<SceKernelSpinlock>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Spinlock<T> {}
unsafe impl<T: Send> Send for Spinlock<T> {}

pub struct SpinlockGuard<'a, T> {
    lock: &'a Spinlock<T>,
    intr_status: SceKernelIntrStatus,
}

impl<T> Spinlock<T> {
    pub const fn new(val: T) -> Self {
        Self {
            lock: UnsafeCell::new(0),
            data: UnsafeCell::new(val),
        }
    }

    pub fn lock(&self) -> SpinlockGuard<'_, T> {
        let intr_status = unsafe { ksceKernelSpinlockLowLockCpuSuspendIntr(self.lock.get()) };
        SpinlockGuard {
            lock: self,
            intr_status,
        }
    }
}

impl<T> Deref for SpinlockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinlockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinlockGuard<'_, T> {
    fn drop(&mut self) {
        unsafe {
            ksceKernelSpinlockLowUnlockCpuResumeIntr(self.lock.lock.get(), self.intr_status);
        }
    }
}
