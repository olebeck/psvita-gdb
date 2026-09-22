use core::panic::PanicInfo;

use crate::println;

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    println!("panic: {}", info);
    loop {}
}
