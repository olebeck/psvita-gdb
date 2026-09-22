use core::ffi::c_void;

use vitasdk_sys::{
    SceArmCpuRegisters, SceClass, SceExcpHandlingCode, SceExcpKind, SceExcpmgrExceptionContext,
    SceKernelIntrStatus, SceKernelModuleInfo, SceKernelThreadContextInfo, SceUID,
};

fn stub_is_invalid(ptr: *const c_void) -> bool {
    let ptr = (ptr as usize & !1) as *const u32;
    let val = unsafe { *ptr };
    val == 0xe24fc008
}

macro_rules! vitastub {
    ($lib:ident, $name:ident, $flags:expr, $libnid:expr, $funcnid:expr) => {
        core::arch::global_asm!(
            ".arm",
            ".arch armv7a",
            concat!(".section .vitalink.fstubs.", stringify!($lib), ",\"ax\""),
            ".align 4",
            concat!(".global ", stringify!($name)),
            concat!(".type ", stringify!($name), ", %function"),
            concat!(stringify!($name), ":"),
            concat!(".word ", stringify!($flags)),
            concat!(".word ", stringify!($libnid)),
            concat!(".word ", stringify!($funcnid)),
            ".word 0",
            ".previous",
        );
    };
}

macro_rules! vitastub_ver {
    (
        $lib:ident,
        $name:ident,
        $libnid_360:expr, $funcnid_360:expr,
        $libnid_363:expr, $funcnid_363:expr
    ) => {
        paste::paste! {
            vitastub!($lib, [<$name _360>], 0x18, $libnid_360, $funcnid_360);
            vitastub!($lib, [<$name _363>], 0x18, $libnid_363, $funcnid_363);

            core::arch::global_asm!(
                ".section .data.fstubs,\"aw\"",
                ".align 4",
                concat!(".global ", stringify!([<$name _stub>])),
                concat!(".type ", stringify!([<$name _stub>]), ", %object"),
                concat!(stringify!([<$name _stub>]), ":"),
                concat!(".word ", stringify!([<$name _360>])),
                ".previous",

                ".section .text,\"ax\"",
                concat!(".global ", stringify!($name)),
                concat!(".type ", stringify!($name), ", %function"),
                concat!(stringify!($name), ":"),
                "ldr r12, 1f",
                "ldr r12, [r12]",
                "bx  r12",
                ".align 2",
                "1:",
                concat!(".word ", stringify!([<$name _stub>])),
                ".previous",
            );
        }
    };
}

macro_rules! libstub {
    (
        $lib:ident,
        $libnid:expr,
        $(
            (
                $funcnid:expr,
                $name:ident ( $( $arg:ident : $arg_ty:ty ),* $(,)? ) -> $ret:ty
            )
        ),* $(,)?
    ) => {
        $(
            unsafe extern "C" {
                pub unsafe fn $name($( $arg: $arg_ty ),*) -> $ret;
            }
            vitastub!($lib, $name, 0x10, $libnid, $funcnid);
        )*
    };
}

macro_rules! libstub_ver {
    (
        $lib:ident,
        $libnid_360:expr, $libnid_363:expr,
        $(
            (
                $funcnid_360:expr, $funcnid_363:expr,
                $name:ident ( $( $arg:ident : $arg_ty:ty ),* $(,)? ) -> $ret:ty
            )
        ),* $(,)?
    ) => {
        $(
            unsafe extern "C" {
                pub unsafe fn $name($( $arg: $arg_ty ),*) -> $ret;
            }
            vitastub_ver!($lib, $name, $libnid_360, $funcnid_360, $libnid_363, $funcnid_363);
            paste::paste! {
                #[used]
                #[unsafe(link_section = "vita_patch363")]
                static [<$name:upper _PATCH363>]: unsafe extern "C" fn() = {
                    unsafe extern "C" {
                        static mut [<$name _stub>]: unsafe extern "C" fn();
                        fn [<$name _363>]();
                    }
                    unsafe extern "C" fn patch() {
                        unsafe { [<$name _stub>] = core::mem::transmute([<$name _363>] as *const ()) };
                    }
                    patch
                };
            }
        )*
    };
}

unsafe extern "C" {
    unsafe static __start_vita_patch363: unsafe extern "C" fn();
    unsafe static __stop_vita_patch363: unsafe extern "C" fn();
    unsafe fn ksceGUIDGetUIDVectorByClass_360();
}

pub fn init_stubs() {
    if stub_is_invalid(ksceGUIDGetUIDVectorByClass_360 as _) {
        unsafe {
            let mut p = &raw const __start_vita_patch363;
            let end = &raw const __stop_vita_patch363;
            while p < end {
                (*p)();
                p = p.add(1);
            }
        }
    }
}

#[link(name = "SceSysmemForDriver_stub", kind = "static")]
unsafe extern "C" {
    pub unsafe fn ksceKernelCopyFromUserProc(
        pid: SceUID,
        dst: *mut c_void,
        src: *const c_void,
        len: usize,
    ) -> i32;
    pub unsafe fn ksceKernelCpuSuspendIntr() -> SceKernelIntrStatus;
    pub unsafe fn ksceKernelCpuResumeIntr(prev_state: SceKernelIntrStatus) -> SceKernelIntrStatus;
}

libstub_ver!(SceSysmemForKernel, 0x63A519E5, 0x02451F0F,
    (0x30931572, 0x2995558D, ksceKernelCopyToUserProcTextDomain(pid: SceUID, dst: *mut c_void, src: *const c_void, len: usize) -> i32),
    (0xEC7D36EF, 0x52137FA3, ksceGUIDGetUIDVectorByClass(cls: *const SceClass, vis_level: i32, vector: *mut SceUID, num: u32, ret_num: *mut u32) -> i32)
);

libstub!(SceSysrootForKernel, 0x3691DA45,
    (0xEC3124A3, ksceKernelSysrootGetProcessTitleId(pid: SceUID, titleid: *mut i8, len: u32) -> i32)
);

libstub_ver!(SceProcessmgrForKernel, 0x7A69DE86, 0xEB1F8EF7,
    (0x6AECE4CD, 0x93B8E785, ksceKernelSuspendProcess(pid: SceUID, status: i32) -> i32),
    (0x080CDC59, 0x6894499C, ksceKernelResumeProcess(pid: SceUID) -> i32),
    (0xC6820972, 0x98AE4BC8, ksceKernelGetUIDProcessClass() -> *mut SceClass),
    (0x95F9ED94, 0xD20553C6, ksceKernelGetProcessMainThread(pid: SceUID) -> SceUID),
    (0x59FA3216, 0x59FA3216, sceKernelSetPHBP(pid: i32, index: u32, addr: u32, control: u32) -> i32),
    (0x54D7B16A, 0xC55BF6C3, sceKernelSetPHWP(pid: i32, index: u32, addr: u32, control: u32) -> i32),
);

libstub_ver!(SceDebugForKernel, 0x88C17370, 0x13D793B7,
    (0x82D2EDCE, 0x2AABAEDA, ksceKernelDebugPutchar(char: i32) -> i32)
);

type ExcpHandler = unsafe extern "C" fn(
    *mut SceExcpmgrExceptionContext,
    SceExcpHandlingCode,
) -> SceExcpHandlingCode;
libstub_ver!(SceExcpmgrForKernel, 0x4CA0FDD5, 0x1496A5B5,
    (0x03499636, 0x00063675, ksceExcpmgrRegisterHandler(kind: SceExcpKind, priority: i32, handler: ExcpHandler) -> i32)
);

libstub_ver!(SceCpuForKernel, 0x54BF2BAB, 0xA5195D20,
    (0x264DA250, 0x803C84BF, ksceKernelL1IcacheInvalidateEntireAllCore() -> ())
);

libstub!(SceThreadmgrForDriver, 0xE2C40624,
    (0x64E89DE9, ksceKernelSetThreadCpuRegisters(thid: SceUID, registers: *const SceArmCpuRegisters, mask: u32) -> i32),
    (0x49A0B679, ksceKernelSetVfpRegisterForDebugger(thid: SceUID, registers: *const c_void) -> i32)
);

libstub_ver!(SceThreadmgrForKernel, 0xA8CA0EFD, 0x7F8593BA,
    (0xD8B9AC8D, 0x6C1F092F, ksceKernelGetThreadContextInfo(info: *mut SceKernelThreadContextInfo) -> i32)
);

libstub_ver!(SceModulemgrForKernel, 0xC445FA63, 0x92C9FFC2,
    (0x97CF7B4E, 0xB72C75A4, ksceKernelGetModuleList(pid: SceUID, flags1: i32, flags2: i32, modids: *mut SceUID, num: *mut u32) -> i32),
    (0xD269F915, 0xDAA90093, ksceKernelGetModuleInfo(pid: SceUID, modid: SceUID, info: *mut SceKernelModuleInfo) -> i32),
    (0x20A27FA9, 0x679F5144, ksceKernelGetModuleIdByPid(pid: SceUID) -> i32)
);

// SKPLForKernel
unsafe extern "C" {
    pub unsafe fn spl_exec_code(buf: *const c_void, size: usize, arg: u32, copy: bool) -> u32;
}
vitastub!(SKPLForKernel, spl_exec_code, 0x18, 0x9fce5cbf, 0x4b856e73);

pub fn spl_is_loaded() -> bool {
    !stub_is_invalid(spl_exec_code as _)
}
