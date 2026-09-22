use core::fmt;

use vitasdk_sys::{
    SceKernelIntrStatus, ksceKernelSpinlockLowLockCpuSuspendIntr,
    ksceKernelSpinlockLowUnlockCpuResumeIntr,
};

use crate::kernel::ffi::ksceKernelDebugPutchar;

static mut PRINTLN_LOCK: i32 = 0;

pub struct PrintlnGuard {
    intr_status: SceKernelIntrStatus,
}

impl Drop for PrintlnGuard {
    fn drop(&mut self) {
        unsafe {
            ksceKernelSpinlockLowUnlockCpuResumeIntr(&raw mut PRINTLN_LOCK, self.intr_status)
        };
    }
}

pub fn lock_println() -> PrintlnGuard {
    let intr_status = unsafe { ksceKernelSpinlockLowLockCpuSuspendIntr(&raw mut PRINTLN_LOCK) };
    PrintlnGuard { intr_status }
}

pub struct DebugWriter;

impl fmt::Write for DebugWriter {
    fn write_str(&mut self, value: &str) -> ::core::fmt::Result {
        for byte in value.bytes() {
            unsafe {
                ksceKernelDebugPutchar(byte as _);
            }
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = core::fmt::Write::write_fmt(
            &mut $crate::kernel::printf::DebugWriter,
            format_args!($($arg)*)
        );
    }};
}

#[macro_export]
macro_rules! println {
    () => {{
        let _lock = $crate::kernel::printf::lock_println();
        $crate::print!("\n");
    }};
    ($($arg:tt)*) => {{
        let _lock = $crate::kernel::printf::lock_println();
        $crate::print!($($arg)*);
        $crate::print!("\n");
    }};
}
