use core::{
    ffi::CStr,
    ptr::{null, null_mut},
};

use vitasdk_sys::{
    SCE_NET_AF_INET, SCE_NET_IPPROTO_TCP, SCE_NET_SOCK_STREAM, SCE_NET_TCP_NODELAY, SceNetInAddr,
    SceNetSockaddr, SceNetSockaddrIn, ksceNetAccept, ksceNetBind, ksceNetClose, ksceNetListen,
    ksceNetSendto, ksceNetSetsockopt, ksceNetSocket,
};

use crate::{kernel::utils::SceError, sce_call};

pub struct TcpSocket(i32);

impl TcpSocket {
    pub fn send(&self, buf: &[u8]) -> Result<usize, SceError> {
        let n = sce_call!(ksceNetSendto(
            self.raw(),
            buf.as_ptr() as _,
            buf.len() as _,
            0,
            null(),
            0
        ))?;
        Ok(n as usize)
    }

    pub fn raw(&self) -> i32 {
        self.0
    }

    pub fn close(&mut self) {
        if self.0 >= 0 {
            unsafe { ksceNetClose(self.0) };
            self.0 = -1;
        }
    }
}

impl Drop for TcpSocket {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct TcpListener {
    socket: i32,
}

impl TcpListener {
    pub fn listen(port: u16, name: &CStr) -> Result<TcpListener, SceError> {
        let socket = sce_call!(ksceNetSocket(
            name.as_ptr() as _,
            SCE_NET_AF_INET as _,
            SCE_NET_SOCK_STREAM as _,
            SCE_NET_IPPROTO_TCP as _
        ))?;
        sce_call!(ksceNetBind(
            socket,
            &SceNetSockaddrIn {
                sin_addr: SceNetInAddr { s_addr: 0 },
                sin_family: SCE_NET_AF_INET as _,
                sin_len: size_of::<SceNetSockaddrIn>() as _,
                sin_port: port.to_be(),
                sin_vport: 0,
                sin_zero: [0, 0, 0, 0, 0, 0],
            } as *const _ as *const SceNetSockaddr,
            size_of::<SceNetSockaddrIn>() as _
        ))?;
        sce_call!(ksceNetListen(socket, 128))?;
        Ok(TcpListener { socket })
    }

    pub fn accept(&self) -> Result<TcpSocket, SceError> {
        let socket = sce_call!(ksceNetAccept(self.socket, null_mut(), null_mut()))?;
        sce_call!(ksceNetSetsockopt(
            socket,
            SCE_NET_IPPROTO_TCP as _,
            SCE_NET_TCP_NODELAY as _,
            &1i32 as *const _ as _,
            4
        ))?;
        Ok(TcpSocket(socket))
    }

    pub fn close(&mut self) {
        if self.socket >= 0 {
            unsafe { ksceNetClose(self.socket) };
            self.socket = -1;
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.close();
    }
}
