use gdbstub::common::{Signal, Tid};
use gdbstub::stub::{
    DisconnectReason, GdbStub, GdbStubError, MultiThreadStopReason,
    state_machine::GdbStubStateMachine,
};
use vitasdk_sys::SCE_EVENT_WAITCLEAR_PAT;

use crate::gdb::sessions::ExceptionEvent;
use crate::gdb::tcpconn::{ReadResult, TcpConn};
use crate::{
    gdb::{
        sessions::{EV_WAKE_WORKER, ExceptionKind},
        target::VitaTarget,
    },
    kernel::utils::{SceError, halt_process},
    println,
};

pub fn run_session(
    gdb: GdbStub<'_, VitaTarget, TcpConn>,
    target: &mut VitaTarget,
) -> Result<DisconnectReason, GdbStubError<SceError, SceError>> {
    let mut gdb = gdb.run_state_machine(target)?;

    loop {
        gdb = match gdb {
            GdbStubStateMachine::Idle(mut gdb) => match next_byte(target, gdb.borrow_conn()) {
                Ok(Incoming::Byte(byte)) => gdb.incoming_data(target, byte)?,
                Ok(Incoming::Stop(_reason)) => {
                    println!("eventloop: stop in idle");
                    break Ok(DisconnectReason::Disconnect);
                }
                Ok(Incoming::Closed) => {
                    println!("eventloop: connection closed");
                    break Ok(DisconnectReason::Disconnect);
                }
                Err(err) => {
                    println!("eventloop: io error {err}");
                    break Ok(DisconnectReason::Disconnect);
                }
            },

            GdbStubStateMachine::Running(mut gdb) => {
                println!("GdbStubStateMachine::Running");
                match next_event_or_byte(target, gdb.borrow_conn()) {
                    Ok(Incoming::Byte(byte)) => gdb.incoming_data(target, byte)?,
                    Ok(Incoming::Stop(reason)) => gdb.report_stop(target, reason)?,
                    Ok(Incoming::Closed) => {
                        println!("eventloop: connection closed");
                        break Ok(DisconnectReason::Disconnect);
                    }
                    Err(err) => {
                        println!("eventloop: io error {err}");
                        break Ok(DisconnectReason::Disconnect);
                    }
                }
            }

            GdbStubStateMachine::CtrlCInterrupt(gdb) => {
                println!("GdbStubStateMachine::CtrlCInterrupt");
                let reason = interrupt_target(target);
                gdb.interrupt_handled(target, reason)?
            }

            GdbStubStateMachine::Disconnected(gdb) => {
                println!("GdbStubStateMachine::Disconnected");
                break Ok(gdb.get_reason());
            }
        };
    }
}

enum Incoming {
    Byte(u8),
    Stop(MultiThreadStopReason<u32>),
    Closed,
}

fn next_event_or_byte(target: &mut VitaTarget, conn: &mut TcpConn) -> Result<Incoming, SceError> {
    loop {
        // has the process detached
        if target.detached {
            target.detached = false;
            return Ok(Incoming::Stop(MultiThreadStopReason::Exited(0)));
        }

        // was there an async event
        if let Some(session) = target.session.as_ref() {
            let inner = session.inner();
            if inner.pop_exited() {
                return Ok(Incoming::Stop(MultiThreadStopReason::Exited(0)));
            }
            if let Some(tid) = inner.pop_step_finished() {
                return Ok(Incoming::Stop(MultiThreadStopReason::SignalWithThread {
                    tid: Tid::new(tid as usize).unwrap(),
                    signal: Signal::SIGTRAP,
                }));
            }
            if let Some(ev) = inner.pop_excp() {
                return Ok(Incoming::Stop(stop_reason_from(ev)));
            }
        };

        // did any data come in
        match conn.read() {
            ReadResult::Byte(byte) => return Ok(Incoming::Byte(byte)),
            ReadResult::Closed => return Ok(Incoming::Closed),
            ReadResult::Err(err) => return Err(err),
            ReadResult::None => (),
        };

        // wait for any event
        target
            .evflag
            .wait(EV_WAKE_WORKER, SCE_EVENT_WAITCLEAR_PAT)?;
    }
}

fn next_byte(target: &mut VitaTarget, conn: &mut TcpConn) -> Result<Incoming, SceError> {
    loop {
        if let Some(session) = target.session.as_ref() {
            let inner = session.inner();
            if inner.pop_exited() {
                return Ok(Incoming::Stop(MultiThreadStopReason::Exited(0)));
            }
        }

        // did any data come in
        match conn.read() {
            ReadResult::Byte(byte) => return Ok(Incoming::Byte(byte)),
            ReadResult::Closed => return Ok(Incoming::Closed),
            ReadResult::Err(err) => return Err(err),
            ReadResult::None => (),
        };

        // wait for any event
        target
            .evflag
            .wait(EV_WAKE_WORKER, SCE_EVENT_WAITCLEAR_PAT)?;
    }
}

fn stop_reason_from(ev: ExceptionEvent) -> MultiThreadStopReason<u32> {
    match ev {
        ExceptionEvent::HwBreak { tid } => {
            MultiThreadStopReason::HwBreak(Tid::new(tid as usize).unwrap())
        }
        ExceptionEvent::Watch { tid, addr, kind } => MultiThreadStopReason::Watch {
            tid: Tid::new(tid as usize).unwrap(),
            kind,
            addr,
        },
        ExceptionEvent::SwBreak { tid } => {
            MultiThreadStopReason::SwBreak(Tid::new(tid as usize).unwrap())
        }
        ExceptionEvent::Exception { tid, kind } => MultiThreadStopReason::SignalWithThread {
            tid: Tid::new(tid as usize).unwrap(),
            signal: match kind {
                ExceptionKind::Dabt => Signal::SIGSEGV,
                ExceptionKind::Pabt => Signal::SIGBUS,
                ExceptionKind::Undef => Signal::SIGILL,
            },
        },
    }
}

fn interrupt_target(target: &mut VitaTarget) -> Option<MultiThreadStopReason<u32>> {
    let Some(pid) = target.pid() else {
        return Some(MultiThreadStopReason::Signal(Signal::SIGINT));
    };

    match halt_process(pid) {
        Ok(tid) => Some(MultiThreadStopReason::SignalWithThread {
            tid: Tid::new(tid as usize).unwrap(),
            signal: Signal::SIGINT,
        }),
        Err(err) => {
            println!("interrupt: {err}");
            Some(MultiThreadStopReason::Signal(Signal::SIGINT))
        }
    }
}
