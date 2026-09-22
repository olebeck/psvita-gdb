use core::{
    cell::UnsafeCell,
    ptr::null_mut,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use gdbstub::conn::Connection;
use vitasdk_sys::{SCE_EVENT_WAITCLEAR_PAT, ksceNetRecvfrom};

use crate::{
    gdb::sessions::{EV_WAKE_READER, EV_WAKE_WORKER},
    kernel::{
        event_flag::EventFlagRef, tcp_socket::TcpSocket, thread::JoinableThread, utils::SceError,
    },
    println, sce_call,
};

const MAX_CONNS: usize = 4;
const BUFFER_SIZE: usize = 0x40;

struct ConnState {
    claimed: AtomicBool,
    buf: UnsafeCell<[u8; BUFFER_SIZE]>,
    len: AtomicUsize,
    closed: AtomicBool,
    err: UnsafeCell<Option<SceError>>,
}

unsafe impl Sync for ConnState {}

impl ConnState {
    const fn new() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            buf: UnsafeCell::new([0u8; BUFFER_SIZE]),
            len: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            err: UnsafeCell::new(None),
        }
    }

    fn reset(&self) {
        self.len.store(0, Ordering::Release);
        self.closed.store(false, Ordering::Release);
        unsafe { *self.err.get() = None }
    }
}

static CONN_POOL: [ConnState; MAX_CONNS] = [const { ConnState::new() }; MAX_CONNS];

fn acquire_state() -> Option<&'static ConnState> {
    for state in CONN_POOL.iter() {
        if state
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            state.reset();
            return Some(state);
        }
    }
    None
}

fn release_state(state: &'static ConnState) {
    state.claimed.store(false, Ordering::Release);
}

pub enum ReadResult {
    Byte(u8),
    Closed,
    Err(SceError),
    None,
}

pub struct TcpConn {
    socket: TcpSocket,
    evflag: EventFlagRef,
    thread: Option<JoinableThread<NetRxArg>>,
    state: &'static ConnState,
    read_len: usize,
    write_buffer: [u8; BUFFER_SIZE],
    write_len: usize,
}

impl TcpConn {
    pub fn new(socket: TcpSocket, evflag: EventFlagRef) -> Result<Self, SceError> {
        let Some(state) = acquire_state() else {
            return Err(SceError::new(-1, "acquire_state"));
        };
        let thread = JoinableThread::create(c"net_rx", 0x40, 0x1000)?;
        thread.start(net_rx_thread, (socket.raw(), evflag, state))?;
        Ok(Self {
            socket,
            evflag,
            thread: Some(thread),
            state,
            read_len: 0,
            write_buffer: [0; BUFFER_SIZE],
            write_len: 0,
        })
    }

    pub fn read(&mut self) -> ReadResult {
        if self.state.closed.load(Ordering::Acquire) {
            if let Some(err) = unsafe { *self.state.err.get() } {
                return ReadResult::Err(err);
            }
            return ReadResult::Closed;
        }
        let len = self.state.len.load(Ordering::Acquire);
        if len == 0 {
            return ReadResult::None;
        }
        let byte = unsafe { &mut *self.state.buf.get() }[self.read_len];
        self.read_len += 1;
        if self.read_len == len {
            self.read_len = 0;
            self.state.len.store(0, Ordering::Relaxed);
            let _ = self.evflag.set(EV_WAKE_READER);
        }
        ReadResult::Byte(byte)
    }

    fn flush_write_buffer(&mut self) -> Result<(), SceError> {
        while self.write_len > 0 {
            let n = self.socket.send(&self.write_buffer[..self.write_len])?;
            if n < self.write_len {
                self.write_buffer.copy_within(n..self.write_len, 0);
                self.write_len -= n;
            } else {
                self.write_len = 0;
            }
        }
        Ok(())
    }

    fn close(&mut self) {
        self.state.closed.store(true, Ordering::Release);
        self.socket.close();
        let _ = self.evflag.set(EV_WAKE_READER);
        if let Some(thread) = self.thread.take() {
            if let Err(err) = thread.join() {
                println!("net_reader join: {err}");
            }
        }
        release_state(self.state);
    }
}

impl Drop for TcpConn {
    fn drop(&mut self) {
        self.close();
    }
}

impl Connection for TcpConn {
    type Error = SceError;

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        if self.write_len == self.write_buffer.len() {
            self.flush_write_buffer()?;
        }
        self.write_buffer[self.write_len] = byte;
        self.write_len += 1;
        if self.write_len == self.write_buffer.len() {
            self.flush_write_buffer()?
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.flush_write_buffer()
    }
}

type NetRxArg = (i32, EventFlagRef, &'static ConnState);

fn net_rx_thread(arg: NetRxArg) {
    let (socket, evflag, state) = arg;
    loop {
        if state.closed.load(Ordering::Acquire) {
            return;
        }
        if state.len.load(Ordering::Acquire) != 0 {
            if let Err(err) = evflag.wait(EV_WAKE_READER, SCE_EVENT_WAITCLEAR_PAT) {
                println!("wait EV_WAKE_READER: {err}")
            }
            continue;
        }

        let buf = unsafe { &mut *state.buf.get() };
        let n = match sce_call!(ksceNetRecvfrom(
            socket,
            buf.as_mut_ptr() as _,
            buf.len() as _,
            0,
            null_mut(),
            null_mut()
        )) {
            Ok(n) => n,
            Err(err) => {
                println!("net_rx_thread: {err}");
                unsafe { *state.err.get() = Some(err) };
                let _ = evflag.set(EV_WAKE_WORKER);
                return;
            }
        };
        if n == 0 {
            state.closed.store(true, Ordering::Release);
            let _ = evflag.set(EV_WAKE_WORKER);
            return;
        }
        state.len.store(n as _, Ordering::Release);
        let _ = evflag.set(EV_WAKE_WORKER);
    }
}
