use vstd::prelude::*;

verus! {

// Offset-only experiment. An acknowledgment is a trusted input, not a disk proof.
pub struct Stream {
    pub received: u64,
    pub durable: u64,
    pub sent: u64,
    pub capacity: u64,
    pub strict: bool,
    pub log_failed: bool,
    pub closed: bool,
}

impl Stream {
    pub open spec fn valid(&self) -> bool {
        self.sent <= self.received
        && self.durable <= self.received
        && self.received - self.sent <= self.capacity
        && (self.strict ==> self.sent <= self.durable)
        && (self.strict && self.log_failed ==> self.closed)
    }

    pub fn new(capacity: u64, strict: bool) -> (s: Self)
        ensures s.valid(), s.received == 0, s.sent == 0, s.durable == 0,
                s.capacity == capacity, s.strict == strict,
    {
        Stream { received: 0, durable: 0, sent: 0, capacity,
                 strict, log_failed: false, closed: false }
    }

    pub fn receive(&mut self, count: u64) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).sent == old(self).sent,
                final(self).durable == old(self).durable,
                final(self).strict == old(self).strict,
                final(self).capacity == old(self).capacity,
                accepted ==> final(self).received == old(self).received + count,
                !accepted ==> final(self).received == old(self).received,
    {
        if self.closed || count > u64::MAX - self.received
            || count > self.capacity - (self.received - self.sent) {
            return false;
        }
        self.received = self.received + count;
        true
    }

    pub fn acknowledge(&mut self, offset: u64) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).received == old(self).received,
                final(self).sent == old(self).sent, final(self).strict == old(self).strict,
                accepted ==> final(self).durable == offset,
                !accepted ==> final(self).durable == old(self).durable,
    {
        if self.closed || self.log_failed || offset < self.durable
            || offset > self.received { return false; }
        self.durable = offset;
        true
    }

    // sent denotes authorized submission, not confirmed application delivery.
    pub fn send(&mut self, count: u64) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).received == old(self).received,
                final(self).durable == old(self).durable,
                final(self).strict == old(self).strict,
                accepted ==> final(self).sent == old(self).sent + count,
                !accepted ==> final(self).sent == old(self).sent,
    {
        if self.closed || count > self.received - self.sent { return false; }
        if self.strict && count > self.durable - self.sent { return false; }
        self.sent = self.sent + count;
        true
    }

    pub fn fail_log(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).log_failed,
                final(self).strict == old(self).strict,
                final(self).strict ==> final(self).closed,
                !final(self).strict ==> final(self).closed == old(self).closed,
                final(self).sent == old(self).sent,
    {
        self.log_failed = true;
        if self.strict { self.closed = true; }
    }

    pub fn cancel(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).closed, final(self).sent == old(self).sent,
    {
        self.closed = true;
    }
}
}

fn main() {
    let mut strict = Stream::new(4, true);
    assert!(strict.receive(4));
    assert!(!strict.receive(1));
    assert!(!strict.send(1));
    assert!(strict.acknowledge(2));
    assert!(strict.send(2));
    strict.fail_log();
    assert!(!strict.send(1));

    let mut available = Stream::new(4, false);
    assert!(available.receive(4));
    available.fail_log();
    assert!(available.send(4));
    assert!(available.receive(4));
    available.cancel();
    assert!(!available.send(1));
    println!("strict and availability-first scenarios passed");
}
