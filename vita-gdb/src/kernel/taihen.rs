use core::{
    cell::UnsafeCell,
    ffi::{CStr, c_char, c_void},
};

use vitasdk_sys::SceUID;

use crate::{kernel::utils::SceError, sce_call};

#[repr(transparent)]
pub struct Ref(UnsafeCell<*const TaiHookUser>);
unsafe impl Sync for Ref {}

impl Ref {
    pub const fn new() -> Ref {
        Ref(UnsafeCell::new(core::ptr::null()))
    }

    pub fn next(&self) -> Option<Ref> {
        let ptr = unsafe { *self.0.get() };
        if ptr.is_null() {
            None
        } else {
            let next_ptr = unsafe { (*ptr).next };
            if next_ptr.is_null() {
                None
            } else {
                Some(Ref(UnsafeCell::new(next_ptr)))
            }
        }
    }

    pub fn func(&self) -> *const c_void {
        let ptr = unsafe { *self.0.get() };
        if ptr.is_null() {
            core::ptr::null()
        } else {
            unsafe { (*ptr).func }
        }
    }

    pub fn old(&self) -> *const c_void {
        let ptr = unsafe { *self.0.get() };
        if ptr.is_null() {
            core::ptr::null()
        } else {
            unsafe { (*ptr).old }
        }
    }
}

#[repr(C)]
pub struct TaiHookUser {
    pub next: *const TaiHookUser,
    pub func: *const c_void,
    pub old: *const c_void,
}

#[link(name = "taihenForKernel_stub", kind = "static")]
unsafe extern "C" {
    pub unsafe fn taiHookFunctionImportForKernel(
        pid: SceUID,
        hook: *mut Ref,
        module: *const c_char,
        library_nid: u32,
        func_nid: u32,
        hook_func: *const c_void,
    ) -> i32;
    pub unsafe fn taiHookReleaseForKernel(tai_uid: SceUID, hook: &Ref) -> i32;
}

pub fn hook_import(
    pid: SceUID,
    module: &CStr,
    library_nid: u32,
    func_nid: u32,
    hook_func: *const c_void,
    hook_ref: &Ref,
) -> Result<i32, SceError> {
    let hook_ref = hook_ref as *const _ as *mut _;
    sce_call!(taiHookFunctionImportForKernel(
        pid,
        hook_ref,
        module.as_ptr(),
        library_nid,
        func_nid,
        hook_func
    ))
}

pub fn release(uid: SceUID, hook_ref: &Ref) {
    sce_call!(taiHookReleaseForKernel(uid, hook_ref)).unwrap();
}

#[macro_export]
macro_rules! tai_continue {
    ($fn_ty:ty, $hook:expr $(, $arg:expr)* $(,)?) => {{
        unsafe {
            match $hook.next() {
                Some(next) => {
                    let f = ::core::mem::transmute::<*const ::core::ffi::c_void, $fn_ty>(next.func());
                    f($($arg),*)
                },
                None => {
                    let f = ::core::mem::transmute::<*const ::core::ffi::c_void, $fn_ty>($hook.old());
                    f($($arg),*)
                }
            }
        }
    }};
}

#[macro_export]
macro_rules! hook {
    (
        fn $name:ident($($arg:ident: $ty:ty),* $(,)?) -> $ret:ty
        as $orig:ident
        $body:block
    ) => {
        paste::paste! {
            #[allow(non_camel_case_types, non_upper_case_globals)]
            type [<$name:camel Fn>] = extern "C" fn($($arg: $ty),*) -> $ret;

            #[allow(non_upper_case_globals)]
            static [<$name _ref>]: $crate::kernel::taihen::Ref = $crate::kernel::taihen::Ref::new();
            #[allow(non_upper_case_globals)]
            #[used]
            static [<$name _uid>]: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

            #[allow(non_snake_case)]
            extern "C" fn [<$name>]($($arg: $ty),*) -> $ret {
                #[allow(unused_variables)]
                let $orig = |$($arg: $ty),*| -> $ret {
                    tai_continue!([<$name:camel Fn>], &[<$name _ref>], $($arg),*)
                };
                $body
            }
        }
    };
}

#[macro_export]
macro_rules! hook_import {
    ($pid:expr, $module:expr, $lib_nid:expr, $func_nid:expr, $hook:ident) => {
        paste::paste! {
            {
                match $crate::kernel::taihen::hook_import(
                    $pid,
                    $module,
                    $lib_nid,
                    $func_nid,
                    $hook as _,
                    &[<$hook _ref>],
                ) {
                    Ok(uid) => {
                        [<$hook _uid>].store(uid, core::sync::atomic::Ordering::Release);
                        Ok(())
                    },
                    Err(err) => Err(err)
                }
            }
        }
    };
}
