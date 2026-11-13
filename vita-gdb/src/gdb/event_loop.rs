use gdbstub::common::{Signal, Tid};
use gdbstub::stub::{DisconnectReason, GdbStub, GdbStubError, state_machine::GdbStubStateMachine};
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

    let mut ctrl_c = false;
    loop {
        gdb = match gdb {
            GdbStubStateMachine::Idle(mut gdb) => {
                if ctrl_c {
                    ctrl_c = false;
                }
                match next_byte(target, gdb.borrow_conn()) {
                    Ok(Incoming::Byte(byte)) => gdb.incoming_data(target, byte)?,
                    Ok(Incoming::Closed) => {
                        println!("eventloop: connection closed");
                        break Ok(DisconnectReason::Disconnect);
                    }
                    Ok(ev) => {
                        println!("eventloop: unexpected event {ev:?} in idle");
                        break Ok(DisconnectReason::Disconnect);
                    }
                    Err(err) => {
                        println!("eventloop: io error {err}");
                        break Ok(DisconnectReason::Disconnect);
                    }
                }
            }

            GdbStubStateMachine::Running(mut gdb) => {
                if ctrl_c {
                    ctrl_c = false;
                    let Some(pid) = target.pid() else {
                        break Ok(DisconnectReason::Disconnect);
                    };
                    match halt_process(pid) {
                        Err(err) => {
                            println!("halt_process: {err}");
                            break Ok(DisconnectReason::Disconnect);
                        }
                        Ok(tid) => {
                            let tid = unsafe { Tid::new_unchecked(tid as _) };
                            gdb.report_stop(target)
                                .signal_with_thread(Signal::SIGINT, tid)?
                                .done()?
                        }
                    }
                } else {
                    let ev = match next_event_or_byte(target, gdb.borrow_conn()) {
                        Ok(ev) => ev,
                        Err(err) => {
                            println!("eventloop: io error {err}");
                            break Ok(DisconnectReason::Disconnect);
                        }
                    };
                    match ev {
                        Incoming::Byte(byte) => gdb.incoming_data(target, byte)?,

                        Incoming::Exception(excp) => {
                            let report = gdb.report_stop(target);
                            match excp {
                                ExceptionEvent::Exception { tid, kind } => {
                                    let signal = match kind {
                                        ExceptionKind::Dabt => Signal::SIGSEGV,
                                        ExceptionKind::Pabt => Signal::SIGBUS,
                                        ExceptionKind::Undef => Signal::SIGILL,
                                    };
                                    let tid = unsafe { Tid::new_unchecked(tid as _) };
                                    report.signal_with_thread(signal, tid)?.done()?
                                }
                                ExceptionEvent::HwBreak { tid } => {
                                    let tid = unsafe { Tid::new_unchecked(tid as _) };
                                    report.hwbreak(tid)?.done()?
                                }
                                ExceptionEvent::SwBreak { tid } => {
                                    let tid = unsafe { Tid::new_unchecked(tid as _) };
                                    report.swbreak(tid)?.done()?
                                }
                                ExceptionEvent::Watch { tid, addr, kind } => {
                                    let tid = unsafe { Tid::new_unchecked(tid as _) };
                                    report.watch(tid, kind, addr)?.done()?
                                }
                            }
                        }

                        Incoming::StepDone => gdb.report_stop(target).done_step()?,

                        Incoming::Exited(code) => gdb.report_stop(target).exited(code)?,

                        Incoming::Closed => {
                            println!("eventloop: connection closed");
                            break Ok(DisconnectReason::Disconnect);
                        }
                    }
                }
            }

            GdbStubStateMachine::CtrlCInterrupt(gdb) => {
                ctrl_c = true;
                gdb.interrupt_handled()
            }

            GdbStubStateMachine::Disconnected(gdb) => {
                println!("GdbStubStateMachine::Disconnected");
                break Ok(gdb.get_reason());
            }
        };
    }
}

#[derive(Debug, Clone, Copy)]
enum Incoming {
    Byte(u8),
    Exception(ExceptionEvent),
    StepDone,
    Exited(u8),
    Closed,
}

fn next_event_or_byte(target: &mut VitaTarget, conn: &mut TcpConn) -> Result<Incoming, SceError> {
    loop {
        // was there an async event
        if let Some(session) = target.session.as_ref() {
            let inner = session.inner();
            if inner.pop_exited() {
                return Ok(Incoming::Exited(0));
            }
            if let Some(_tid) = inner.pop_step_finished() {
                return Ok(Incoming::StepDone);
            }
            if let Some(ev) = inner.pop_excp() {
                return Ok(Incoming::Exception(ev));
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
                return Ok(Incoming::Exited(0));
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
