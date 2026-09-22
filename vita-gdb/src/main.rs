#![no_std]
#![no_main]

mod cp14;
mod gdb;
mod kernel;
mod mep;

pub const GDB_PORT: u16 = 31337;

#[unsafe(no_mangle)]
pub extern "C" fn module_start(_argc: isize, _argv: *const u8) -> isize {
    main();
    0
}

fn main() {
    kernel::ffi::init_stubs();
    gdb::handlers::register_exception_handlers();
    gdb::handlers::register_process_handlers();
    gdb::handlers::register_sysevent_handler();

    if let Err(err) = cp14::enable_debug() {
        println!("enable_debug: {err}");
        return;
    }

    if let Err(err) = gdb::main::start_gdb() {
        println!("start_gdb: {err}");
    }
}
