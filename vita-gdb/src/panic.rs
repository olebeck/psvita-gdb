use core::panic::PanicInfo;

use crate::{
    kernel::{
        syscon::{SYSCON_COLD_RESET, syscon_cmd},
        thread::delay_thread,
    },
    println,
};

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    println!("panic: {}", info);
    delay_thread(5 * 1000 * 1000);
    let _ = syscon_cmd(SYSCON_COLD_RESET);
    loop {}
}
