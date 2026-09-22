use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicUsize, Ordering},
};

pub struct MpscRing<T, const CAP: usize = 16> {
    buf: [MaybeUninit<T>; CAP],
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl<T, const CAP: usize> MpscRing<T, CAP> {
    pub const fn new() -> Self {
        Self {
            buf: [const { MaybeUninit::uninit() }; CAP],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    pub fn push(&self, s: T) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let next = (head + 1) % CAP;
        if next == self.tail.load(Ordering::Acquire) {
            return false;
        }
        unsafe {
            let slot = self.buf.as_ptr().add(head) as *mut MaybeUninit<T>;
            slot.write(MaybeUninit::new(s));
        }
        self.head.store(next, Ordering::Release);
        true
    }

    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }
        let s = unsafe { self.buf.as_ptr().add(tail).read().assume_init() };
        self.tail.store((tail + 1) % CAP, Ordering::Release);
        Some(s)
    }

    pub fn clear(&self) {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Relaxed);

        let mut idx = tail;
        while idx != head {
            unsafe { self.buf.as_ptr().add(idx).read().assume_init_drop() };
            idx = (idx + 1) % CAP;
        }

        self.tail.store(head, Ordering::Release);
    }

    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Relaxed);
        head - tail
    }
}
