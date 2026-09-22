use gdbstub::stub::GdbStubBuilder;

use crate::gdb::event_loop;
use crate::gdb::target::VitaTarget;
use crate::gdb::tcpconn::TcpConn;
use crate::kernel::tcp_socket::{TcpListener, TcpSocket};
use crate::kernel::thread::{DetachedThread, delay_thread};
use crate::kernel::{event_flag::EventFlag, utils::SceError};
use crate::{GDB_PORT, println};

pub fn start_gdb() -> Result<(), SceError> {
    let thread = DetachedThread::create(c"gdb_main", 0x40, 0x4000)?;
    thread.start(main_thread, ())
}

fn main_thread(_: ()) {
    loop {
        delay_thread(1000 * 1000);
        let listener = match TcpListener::listen(GDB_PORT, c"gdb") {
            Err(err) => {
                println!("listen: {err}");
                continue;
            }
            Ok(listener) => listener,
        };
        println!("gdb listening port={GDB_PORT}");

        loop {
            let socket = match listener.accept() {
                Err(err) => break println!("accept: {err}"),
                Ok(conn) => conn,
            };
            if let Err(err) = handle_connection(socket) {
                println!("handle_connection: {err}");
            }
        }
    }
}

fn handle_connection(socket: TcpSocket) -> Result<(), SceError> {
    let thread = DetachedThread::create(c"gdb_worker", 0x40, 0x4000)?;
    thread.start(gdb_thread, socket)
}

fn gdb_thread(socket: TcpSocket) {
    let mut buf = [0; 0x1000];

    let evflag = match EventFlag::new(c"GdbEvtFlag") {
        Ok(flag) => flag,
        Err(err) => return println!("EventFlag::new: {err}"),
    };

    let conn = match TcpConn::new(socket, evflag.as_ref()) {
        Ok(conn) => conn,
        Err(err) => return println!("TcpConn::new: {err}"),
    };

    let gdb = match GdbStubBuilder::new(conn)
        .with_packet_buffer(&mut buf)
        .build()
    {
        Ok(gdb) => gdb,
        Err(err) => return println!("err building: {err}"),
    };

    let mut target = VitaTarget::new(evflag.as_ref());
    match event_loop::run_session(gdb, &mut target) {
        Err(err) => {
            println!("err={err}");
        }
        Ok(reason) => {
            println!("reason={reason:?}");
        }
    }
}
