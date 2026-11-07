use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::kernel::spinlock::Spinlock;

pub struct MpscRing<T, const CAP: usize = 16> {
    buf: [MaybeUninit<T>; CAP],
    head: AtomicUsize,
    tail: AtomicUsize,
    lock: Spinlock<()>,
}

impl<T, const CAP: usize> MpscRing<T, CAP> {
    pub const fn new() -> Self {
        Self {
            buf: [const { MaybeUninit::uninit() }; CAP],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            lock: Spinlock::new(()),
        }
    }

    pub fn push(&self, s: T) -> bool {
        let _guard = self.lock.lock();
        let head = self.head.load(Ordering::Relaxed);
        let next = head.wrapping_add(1).checked_rem(CAP).unwrap_or(0);
        if next == self.tail.load(Ordering::Relaxed) {
            return false;
        }
        unsafe {
            let slot = self.buf.as_ptr().add(head) as *mut MaybeUninit<T>;
            slot.write(MaybeUninit::new(s));
        }
        self.head.store(next, Ordering::Relaxed);
        true
    }

    pub fn pop(&self) -> Option<T> {
        let _guard = self.lock.lock();
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Relaxed) {
            return None;
        }
        let s = unsafe { self.buf.as_ptr().add(tail).read().assume_init() };
        self.tail.store(
            tail.wrapping_add(1).checked_rem(CAP).unwrap_or(0),
            Ordering::Relaxed,
        );
        Some(s)
    }

    pub fn clear(&self) {
        let _guard = self.lock.lock();
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Relaxed);

        let mut idx = tail;
        while idx != head {
            unsafe { self.buf.as_ptr().add(idx).read().assume_init_drop() };
            idx = idx.wrapping_add(1).checked_rem(CAP).unwrap_or(0);
        }

        self.tail.store(head, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        let _guard = self.lock.lock();
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Relaxed);
        head.wrapping_add(CAP)
            .wrapping_sub(tail)
            .checked_rem(CAP)
            .unwrap_or(0)
    }
}
