use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Slot<T> {
    turn: AtomicUsize,
    val: UnsafeCell<MaybeUninit<T>>,
}

pub struct MpscRing<T, const CAP: usize = 16> {
    slots: [Slot<T>; CAP],
    head: AtomicUsize,
    tail: AtomicUsize,
}

unsafe impl<T: Send, const CAP: usize> Send for MpscRing<T, CAP> {}
unsafe impl<T: Send, const CAP: usize> Sync for MpscRing<T, CAP> {}

impl<T, const CAP: usize> MpscRing<T, CAP> {
    const CHECK: () = assert!(CAP.is_power_of_two(), "CAP must be a power of two");

    pub const fn new() -> Self {
        let () = Self::CHECK;
        Self {
            slots: [const {
                Slot {
                    turn: AtomicUsize::new(0),
                    val: UnsafeCell::new(MaybeUninit::uninit()),
                }
            }; CAP],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    pub fn push(&self, item: T) -> bool {
        let mut head = self.head.load(Ordering::Relaxed);
        loop {
            let slot = &self.slots[head % CAP];
            let turn = slot.turn.load(Ordering::Acquire);

            if turn == (head / CAP).wrapping_mul(2) {
                match self
                    .head
                    .compare_exchange_weak(head, head.wrapping_add(1), Ordering::Relaxed, Ordering::Relaxed)
                {
                    Ok(_) => {
                        unsafe { (*slot.val.get()).write(item) };
                        slot.turn.store(turn.wrapping_add(1), Ordering::Release);
                        return true;
                    }
                    Err(actual) => head = actual,
                }
            } else {
                let prev = head;
                head = self.head.load(Ordering::Relaxed);
                if head == prev {
                    return false;
                }
            }
        }
    }

    pub unsafe fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let slot = &self.slots[tail % CAP];
        let lap2 = (tail / CAP).wrapping_mul(2);

        if slot.turn.load(Ordering::Acquire) != lap2.wrapping_add(1) {
            return None;
        }

        let item = unsafe { (*slot.val.get()).assume_init_read() };
        slot.turn.store(lap2.wrapping_add(2), Ordering::Release);
        self.tail.store(tail.wrapping_add(1), Ordering::Relaxed);
        Some(item)
    }

    pub unsafe fn clear(&self) { while unsafe { self.pop() }.is_some() {} }

    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        head.wrapping_sub(tail).min(CAP)
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

impl<T, const CAP: usize> Drop for MpscRing<T, CAP> {
    fn drop(&mut self) { while unsafe { self.pop() }.is_some() {} }
}
