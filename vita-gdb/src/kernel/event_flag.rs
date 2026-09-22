use core::{ffi::CStr, ptr::null_mut};

use vitasdk_sys::{
    SCE_KERNEL_ERROR_WAIT_TIMEOUT, SceUID, ksceKernelClearEventFlag, ksceKernelCreateEventFlag,
    ksceKernelDeleteEventFlag, ksceKernelSetEventFlag, ksceKernelWaitEventFlag,
};

use crate::{kernel::utils::SceError, println, sce_call};

const SCE_KERNEL_ATTR_MULTI: u32 = 0x1000;

#[derive(Clone, Copy)]
pub struct EventFlagRef {
    evfid: SceUID,
}

impl EventFlagRef {
    pub fn new(evfid: SceUID) -> Self {
        Self { evfid }
    }

    pub fn set(&self, bits: u32) -> Result<(), SceError> {
        //println!("ksceKernelSetEventFlag({}, {bits:b})", self.evfid);
        sce_call!(ksceKernelSetEventFlag(self.evfid, bits))
            .inspect_err(|err| println!("set: {err}"))?;
        Ok(())
    }

    pub fn clear(&self, bits: u32) -> Result<(), SceError> {
        //println!("ksceKernelClearEventFlag({}, {bits:b})", self.evfid);
        sce_call!(ksceKernelClearEventFlag(self.evfid, !bits))?;
        Ok(())
    }

    pub fn wait_timeout(
        &self,
        bits: u32,
        wait: u32,
        mut timeout: u32,
    ) -> Result<Option<u32>, SceError> {
        let mut out: u32 = 0;
        if let Err(err) = sce_call!(ksceKernelWaitEventFlag(
            self.evfid,
            bits,
            wait,
            &mut out,
            &mut timeout
        )) {
            if err.code == SCE_KERNEL_ERROR_WAIT_TIMEOUT as i32 {
                return Ok(None);
            }
            return Err(err);
        }
        Ok(Some(out))
    }

    pub fn wait(&self, bits: u32, wait: u32) -> Result<u32, SceError> {
        //println!("ksceKernelWaitEventFlag({}, {bits:b})", self.evfid);
        let mut out: u32 = 0;
        sce_call!(ksceKernelWaitEventFlag(
            self.evfid,
            bits,
            wait,
            &mut out,
            null_mut()
        ))
        .inspect_err(|err| println!("wait: {err}"))?;
        //println!("woke: out={out:b} bits={bits:b}");
        Ok(out)
    }
}

pub struct EventFlag {
    evfid: SceUID,
}

impl EventFlag {
    pub fn new(name: &CStr) -> Result<Self, SceError> {
        let evfid = sce_call!(ksceKernelCreateEventFlag(
            name.as_ptr() as _,
            SCE_KERNEL_ATTR_MULTI as _,
            0,
            core::ptr::null_mut()
        ))?;
        Ok(Self { evfid })
    }

    pub fn as_ref(&self) -> EventFlagRef {
        EventFlagRef { evfid: self.evfid }
    }

    pub fn delete(&mut self) -> Result<(), SceError> {
        if self.evfid != 0 {
            sce_call!(ksceKernelDeleteEventFlag(self.evfid))?;
            self.evfid = 0;
        }
        Ok(())
    }
}

impl Drop for EventFlag {
    fn drop(&mut self) {
        let _ = self.delete();
    }
}
