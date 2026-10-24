//! Inline one-item mailbox. Endpoint closure is permanent; wakeups are external.
use vstd::prelude::*;

verus! {
pub struct Mailbox<T> { value: Option<T>, sender_open: bool, receiver_open: bool }
impl<T> Mailbox<T> {
    pub closed spec fn item(&self) -> Option<T> { self.value }
    pub closed spec fn sender_open(&self) -> bool { self.sender_open }
    pub closed spec fn receiver_open(&self) -> bool { self.receiver_open }
    pub closed spec fn valid(&self) -> bool { !self.receiver_open ==> self.value.is_none() }
    pub open spec fn retained_count(&self) -> nat { if self.item().is_some() { 1 } else { 0 } }
    pub fn new() -> (out: Self)
        ensures out.valid(), out.item().is_none(), out.sender_open(), out.receiver_open(),
    { Self { value: None, sender_open: true, receiver_open: true } }
    pub fn is_closed(&self) -> (out: bool)
        ensures out == (!self.sender_open() || !self.receiver_open()),
    { !self.sender_open || !self.receiver_open }
    pub fn is_full(&self) -> (out: bool)
        ensures out == self.item().is_some(),
    { self.value.is_some() }
    pub fn push(&mut self, value: T) -> (out: Result<(), T>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).sender_open() == old(self).sender_open(),
            final(self).receiver_open() == old(self).receiver_open(),
            match out {
                Ok(()) => old(self).sender_open() && old(self).receiver_open() && old(self).item().is_none()
                    && final(self).item() == Some(value),
                Err(returned) => returned == value && final(self).item() == old(self).item()
                    && (!old(self).sender_open() || !old(self).receiver_open() || old(self).item().is_some()),
            },
    {
        if !self.sender_open || !self.receiver_open || self.value.is_some() { return Err(value); }
        self.value = Some(value);
        Ok(())
    }
    pub fn pop(&mut self) -> (out: Option<T>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).item().is_none(), out == old(self).item(),
            final(self).sender_open() == old(self).sender_open(),
            final(self).receiver_open() == old(self).receiver_open(),
    {
        let mut value = None;
        core::mem::swap(&mut value, &mut self.value);
        value
    }
    pub fn close_sender(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), !final(self).sender_open(),
            final(self).receiver_open() == old(self).receiver_open(), final(self).item() == old(self).item(),
    { self.sender_open = false; }
    // Return ownership for destruction outside the synchronization lock.
    pub fn close_receiver(&mut self) -> (out: Option<T>)
        requires old(self).valid(),
        ensures final(self).valid(), !final(self).receiver_open(), final(self).item().is_none(),
            final(self).sender_open() == old(self).sender_open(), out == old(self).item(),
    {
        let value = self.pop();
        self.receiver_open = false;
        value
    }
    pub proof fn slot_bound(&self)
        requires self.valid(),
        ensures self.retained_count() <= 1, (self.retained_count() == 0) == self.item().is_none(),
            !self.receiver_open() ==> self.retained_count() == 0,
    {}
}
}
