//! Inline one-item mailbox. Endpoint closure is permanent; wakeups are external.
use vstd::prelude::*;

verus! {
// Receiver closure transfers the charge as well as the value. Reporting actual
// destruction remains an adapter obligation; extracting the value is not cleanup.
pub struct Cleanup<T> {
    value: Option<T>,
    started: bool,
    finished: bool,
    occupied: bool,
    #[allow(dead_code)] original: Ghost<Option<T>>,
}
impl<T> Cleanup<T> {
    pub fn new(value: Option<T>) -> (out: Self)
        ensures out.valid(), !out.started(), !out.finished(), out.original() == value,
            out.charged() == (if value.is_some() { 1nat } else { 0nat }),
    {
        let occupied = value.is_some();
        let ghost original = value;
        Self { value, occupied, started: false, finished: false, original: Ghost(original) }
    }
    pub closed spec fn original(&self) -> Option<T> { self.original@ }
    pub closed spec fn started(&self) -> bool { self.started }
    pub closed spec fn finished(&self) -> bool { self.finished }
    pub closed spec fn valid(&self) -> bool {
        self.occupied == self.original().is_some()
            && (self.finished ==> self.started)
            && (if self.started { self.value.is_none() } else { self.value == self.original() })
    }
    pub closed spec fn charged(&self) -> nat {
        if self.occupied && !self.finished { 1 } else { 0 }
    }
    pub fn is_finished(&self) -> (out: bool)
        ensures out == self.finished(),
    { self.finished }
    pub fn retained_count(&self) -> (out: usize)
        ensures out == self.charged(),
    { if self.occupied && !self.finished { 1 } else { 0 } }
    pub fn begin(&mut self) -> (out: Option<T>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).started(),
            final(self).original() == old(self).original(),
            final(self).finished() == old(self).finished(),
            final(self).charged() == old(self).charged(),
            out == (if old(self).started() { None } else { old(self).original() }),
    {
        self.started = true;
        let mut out = None;
        core::mem::swap(&mut out, &mut self.value);
        out
    }
    // Invoke only after the extracted payload's destructor has returned.
    // Panicking destruction must skip this report and strand the enclosing credit.
    pub fn finish(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            final(self).original() == old(self).original(),
            final(self).started() == old(self).started(),
            ok == (old(self).started() && !old(self).finished()),
            ok ==> final(self).finished() && final(self).charged() == 0,
            !ok ==> *final(self) == *old(self),
    {
        if !self.started || self.finished { return false; }
        self.finished = true;
        true
    }
}
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
    pub fn close_receiver_charged(&mut self) -> (out: Cleanup<T>)
        requires old(self).valid(),
        ensures final(self).valid(), !final(self).receiver_open(), final(self).item().is_none(),
            final(self).sender_open() == old(self).sender_open(),
            out.valid(), !out.started(), !out.finished(), out.original() == old(self).item(),
            final(self).retained_count() + out.charged() == old(self).retained_count(),
    {
        let value = self.close_receiver();
        Cleanup::new(value)
    }
    pub proof fn slot_bound(&self)
        requires self.valid(),
        ensures self.retained_count() <= 1, (self.retained_count() == 0) == self.item().is_none(),
            !self.receiver_open() ==> self.retained_count() == 0,
    {}
}
}
