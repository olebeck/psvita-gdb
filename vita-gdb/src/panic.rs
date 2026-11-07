use core::panic::PanicInfo;

use crate::{
    kernel::syscon::{self, SYSCON_COLD_RESET, syscon_cmd},
    println,
};

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    println!("panic: {}", info);
    let _ = syscon_cmd(SYSCON_COLD_RESET);
    loop {}
}
