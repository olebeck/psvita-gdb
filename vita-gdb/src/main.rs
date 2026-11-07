#![no_std]
#![no_main]

mod cp14;
mod gdb;
mod kernel;
mod mep;
mod net_fixup;
mod panic;

//use panic_never as _;

pub const GDB_PORT: u16 = 31337;

#[unsafe(no_mangle)]
pub extern "C" fn module_start(_argc: isize, _argv: *const u8) -> isize {
    main();
    0
}

fn main() {
    kernel::ffi::init_stubs();
    gdb::handlers::register_exception_handlers();
    if let Err(err) = gdb::handlers::register_process_handlers() {
        println!("register_process_handlers {err}");
    }
    if let Err(err) = gdb::handlers::register_sysevent_handler() {
        println!("register_sysevent_handler {err}");
    }
    /*
    if let Err(err) = net_fixup::fixup_netrecv_bug() {
        println!("fixup_netrecv_bug: {err}");
    }
    */

    if let Err(err) = hook_import!(
        0x10005,
        c"SceAppMgr",
        0x4E29D3B6, // SceQafMgrForDriver
        0x7B14DC45,
        SceQafMgrForDriver_7B14DC45_hook
    ) {
        println!("hook_import: {err}");
    }

    if let Err(err) = cp14::enable_debug() {
        println!("enable_debug: {err}");
        return;
    }

    if let Err(err) = gdb::main::start_gdb() {
        println!("start_gdb: {err}");
    }
}

// make SceAppMgr launch app read args
hook!(fn SceQafMgrForDriver_7B14DC45_hook() -> i32 as hook_continue {
    return 1;
});
