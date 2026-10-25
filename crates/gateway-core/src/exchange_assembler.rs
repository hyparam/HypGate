//! Verified grouping of audit records into exchanges for the cloud shipper.
//! Records arrive in file order, interleaved across requests. Each request's
//! body bytes are retained as an ordered prefix of what was received, within a
//! per-exchange byte cap, and the number of open exchanges is bounded. The
//! assembler never reorders, duplicates, or invents bytes; it only drops a
//! suffix when the cap is reached and says so.
use vstd::prelude::*;
use vstd::slice::slice_subrange;
use crate::framing::{Header, append};
use crate::metadata::{self, Completion, RequestStart, ResponseHead};

verus! {
pub open spec fn saturated(n: nat) -> u64 { if n > u64::MAX { u64::MAX } else { n as u64 } }

// The retained bytes are an exact prefix of everything received, and the whole
// of it unless truncation was recorded.
pub open spec fn retained_prefix(kept: Seq<u8>, all: Seq<u8>, truncated: bool) -> bool {
    kept.len() <= all.len() && kept == all.subrange(0, kept.len() as int) && (!truncated ==> kept == all)
}

pub struct Exchange {
    pub tenant: u64,
    pub request: u64,
    pub start: Option<RequestStart>,
    pub head: Option<ResponseHead>,
    pub completion: Option<Completion>,
    pub upload: Vec<u8>,
    pub download: Vec<u8>,
    /// Bytes received in each direction, including any dropped suffix (saturating).
    pub upload_total: u64,
    pub download_total: u64,
    /// Some body bytes were dropped because the per-exchange cap was reached.
    pub truncated: bool,
    /// No completion record was seen: evicted at capacity or at end of input.
    pub incomplete: bool,
    /// Records arrived without an open request start for this request.
    pub orphan: bool,
    upload_all: Ghost<Seq<u8>>,
    download_all: Ghost<Seq<u8>>,
}

impl Exchange {
    pub closed spec fn request_id(&self) -> u64 { self.request }
    pub closed spec fn tenant_id(&self) -> u64 { self.tenant }
    pub closed spec fn is_orphan(&self) -> bool { self.orphan }
    pub closed spec fn is_incomplete(&self) -> bool { self.incomplete }
    pub closed spec fn upload_received(&self) -> Seq<u8> { self.upload_all@ }
    pub closed spec fn download_received(&self) -> Seq<u8> { self.download_all@ }
    pub closed spec fn valid(&self, cap: nat) -> bool {
        self.upload@.len() + self.download@.len() <= cap
            && (self.truncated ==> self.upload@.len() + self.download@.len() == cap)
            && retained_prefix(self.upload@, self.upload_all@, self.truncated)
            && retained_prefix(self.download@, self.download_all@, self.truncated)
            && self.upload_total == saturated(self.upload_all@.len())
            && self.download_total == saturated(self.download_all@.len())
    }

    fn open(tenant: u64, request: u64, start: Option<RequestStart>, orphan: bool) -> (out: Self)
        ensures forall|cap: nat| out.valid(cap), out.tenant == tenant, out.request == request,
            out.start == start, out.head.is_none(), out.completion.is_none(), out.orphan == orphan,
            !out.incomplete, !out.truncated, out.request_id() == request, out.tenant_id() == tenant,
            out.is_orphan() == orphan, !out.is_incomplete(), out.upload_received() == Seq::<u8>::empty(),
            out.download_received() == Seq::<u8>::empty(),
    {
        proof { assert(Seq::<u8>::empty().subrange(0, 0) =~= Seq::<u8>::empty()); }
        Exchange { tenant, request, start, head: None, completion: None, upload: Vec::new(), download: Vec::new(),
            upload_total: 0, download_total: 0, truncated: false, incomplete: false, orphan,
            upload_all: Ghost(Seq::empty()), download_all: Ghost(Seq::empty()) }
    }

    // Append as much of the payload as the cap allows, in order, and record
    // truncation for the rest. Nothing else about the exchange changes.
    fn append_body(&mut self, upload: bool, payload: &[u8], cap: usize)
        requires old(self).valid(cap as nat),
        ensures final(self).valid(cap as nat),
            final(self).tenant == old(self).tenant, final(self).request == old(self).request,
            final(self).start == old(self).start, final(self).head == old(self).head,
            final(self).completion == old(self).completion, final(self).orphan == old(self).orphan,
            final(self).incomplete == old(self).incomplete,
            upload ==> final(self).upload_received() == old(self).upload_received() + payload@
                && final(self).download_received() == old(self).download_received(),
            !upload ==> final(self).download_received() == old(self).download_received() + payload@
                && final(self).upload_received() == old(self).upload_received(),
    {
        let used = self.upload.len() + self.download.len();
        let room = cap - used;
        let take = if payload.len() <= room { payload.len() } else { self.truncated = true; room };
        let kept = slice_subrange(payload, 0, take);
        let ghost was_truncated = old(self).truncated;
        if upload {
            let ghost before = self.upload@;
            let ghost all = self.upload_all@;
            append(&mut self.upload, kept);
            self.upload_all = Ghost(all + payload@);
            self.upload_total = saturating_add(self.upload_total, payload.len() as u64);
            proof { retained_after_append(before, all, kept@, payload@, was_truncated, self.truncated); }
        } else {
            let ghost before = self.download@;
            let ghost all = self.download_all@;
            append(&mut self.download, kept);
            self.download_all = Ghost(all + payload@);
            self.download_total = saturating_add(self.download_total, payload.len() as u64);
            proof { retained_after_append(before, all, kept@, payload@, was_truncated, self.truncated); }
        }
    }
}

// Appending a prefix of the payload to a retained prefix of everything received
// gives a retained prefix of everything received plus the payload.
proof fn retained_after_append(before: Seq<u8>, all: Seq<u8>, kept: Seq<u8>, payload: Seq<u8>,
    was_truncated: bool, truncated: bool)
    requires retained_prefix(before, all, was_truncated), kept.len() <= payload.len(),
        kept == payload.subrange(0, kept.len() as int),
        was_truncated ==> kept.len() == 0,
        truncated == (was_truncated || kept.len() < payload.len()),
    ensures retained_prefix(before + kept, all + payload, truncated),
{
    let kept_new = before + kept; let all_new = all + payload;
    if was_truncated {
        assert(kept_new =~= before);
        assert forall|i: int| 0 <= i < before.len() implies before[i] == all_new[i] by {
            assert(before[i] == all.subrange(0, before.len() as int)[i]);
        }
        assert(kept_new =~= all_new.subrange(0, kept_new.len() as int));
    } else {
        assert(before == all);
        assert forall|i: int| 0 <= i < kept_new.len() implies kept_new[i] == all_new[i] by {
            if i >= before.len() {
                assert(kept[i - before.len()] == payload.subrange(0, kept.len() as int)[i - before.len()]);
            }
        }
        assert(kept_new =~= all_new.subrange(0, kept_new.len() as int));
        if !truncated { assert(kept =~= payload); assert(kept_new =~= all_new); }
    }
}

pub fn saturating_add(a: u64, b: u64) -> (out: u64)
    ensures out == saturated((a + b) as nat),
{
    if a > u64::MAX - b { u64::MAX } else { a + b }
}

/// Index of a request in a duplicate-free open list.
pub open spec fn index_of(open: Seq<u64>, request: u64) -> int {
    choose|i: int| 0 <= i < open.len() && open[i] == request
}

/// The flush pseudo-record kind: evict the oldest open exchange.
pub const FLUSH: u8 = 5;

/// One step of the emission order: how the list of open request ids changes
/// and which request's exchange is emitted, as a function of the record kind
/// and request alone. Body bytes never influence it.
pub open spec fn step(open: Seq<u64>, max_open: nat, kind: u8, request: u64) -> (Seq<u64>, Option<u64>) {
    if kind == 2 {
        if open.contains(request) { (open.remove(index_of(open, request)).push(request), Some(request)) }
        else if open.len() == max_open { (open.drop_first().push(request), Some(open[0])) }
        else { (open.push(request), None) }
    } else if kind == 4 {
        if open.contains(request) { (open.remove(index_of(open, request)), Some(request)) } else { (open, Some(request)) }
    } else if kind == FLUSH {
        if open.len() > 0 { (open.drop_first(), Some(open[0])) } else { (open, None) }
    } else if open.contains(request) { (open, None) } else { (open, Some(request)) }
}

/// The open request ids after a sequence of (kind, request) inputs.
pub open spec fn open_after(inputs: Seq<(u8, u64)>, max_open: nat) -> Seq<u64>
    decreases inputs.len(),
{
    if inputs.len() == 0 { Seq::empty() }
    else { step(open_after(inputs.drop_last(), max_open), max_open, inputs.last().0, inputs.last().1).0 }
}

/// The request ids of the exchanges emitted by a sequence of inputs, in
/// emission order. This is the replay theorem's object: it depends on the
/// record kinds and request ids alone, so the same log replays to the same
/// numbering.
pub open spec fn emitted_requests(inputs: Seq<(u8, u64)>, max_open: nat) -> Seq<u64>
    decreases inputs.len(),
{
    if inputs.len() == 0 { Seq::empty() }
    else {
        let before = emitted_requests(inputs.drop_last(), max_open);
        match step(open_after(inputs.drop_last(), max_open), max_open, inputs.last().0, inputs.last().1).1 {
            Some(request) => before.push(request),
            None => before,
        }
    }
}

/// Replay: the same inputs number the same exchanges. Stated for the record;
/// it holds because `emitted_requests` is a function of its arguments.
pub proof fn replay_is_deterministic(a: Seq<(u8, u64)>, b: Seq<(u8, u64)>, max_open: nat)
    requires a == b,
    ensures emitted_requests(a, max_open) == emitted_requests(b, max_open), open_after(a, max_open) == open_after(b, max_open),
{}

pub struct Assembler { open: Vec<Exchange>, max_open: usize, max_bytes: usize }

impl Assembler {
    pub closed spec fn open_count(&self) -> nat { self.open@.len() }
    pub closed spec fn max_open(&self) -> nat { self.max_open as nat }
    pub closed spec fn max_bytes(&self) -> nat { self.max_bytes as nat }
    pub closed spec fn has_open(&self, request: u64) -> bool {
        exists|i: int| 0 <= i < self.open@.len() && (#[trigger] self.open@[i]).request == request
    }
    /// The open request ids, oldest first.
    pub closed spec fn open_requests(&self) -> Seq<u64> { Seq::new(self.open@.len(), |i: int| self.open@[i].request) }
    pub open spec fn no_duplicates(open: Seq<u64>) -> bool {
        forall|i: int, j: int| 0 <= i < j < open.len() ==> open[i] != open[j]
    }
    /// What a valid assembler guarantees about its open list, for callers outside this module.
    pub proof fn open_requests_valid(&self)
        requires self.valid(),
        ensures Self::no_duplicates(self.open_requests()), self.open_requests().len() <= self.max_open(),
            forall|r: u64| self.has_open(r) == self.open_requests().contains(r),
    {
        assert forall|r: u64| self.has_open(r) == self.open_requests().contains(r) by {
            if self.has_open(r) {
                let i = choose|i: int| 0 <= i < self.open@.len() && (#[trigger] self.open@[i]).request == r;
                assert(self.open_requests()[i] == r);
            }
            if self.open_requests().contains(r) {
                let i = choose|i: int| 0 <= i < self.open_requests().len() && self.open_requests()[i] == r;
                assert(self.open@[i].request == r);
            }
        }
    }
    // In a duplicate-free list the chosen index of a present request is the only one.
    proof fn index_unique(&self, index: int, request: u64)
        requires self.valid(), 0 <= index < self.open@.len(), self.open@[index].request == request,
        ensures index_of(self.open_requests(), request) == index, self.open_requests().contains(request),
    {
        let reqs = self.open_requests();
        assert(reqs[index] == request);
        let c = index_of(reqs, request);
        assert(0 <= c < reqs.len() && reqs[c] == request);
        if c != index {
            if c < index { assert(reqs[c] != reqs[index]); } else { assert(reqs[index] != reqs[c]); }
            assert(false);
        }
    }
    pub closed spec fn valid(&self) -> bool {
        0 < self.max_open && self.open@.len() <= self.max_open
            && forall|i: int| 0 <= i < self.open@.len() ==> (#[trigger] self.open@[i]).valid(self.max_bytes as nat)
                && !self.open@[i].is_orphan() && !self.open@[i].is_incomplete()
            && forall|i: int, j: int| 0 <= i < j < self.open@.len()
                ==> (#[trigger] self.open@[i]).request != (#[trigger] self.open@[j]).request
    }

    pub fn new(max_open: usize, max_bytes: usize) -> (out: Self)
        requires 0 < max_open,
        ensures out.valid(), out.open_count() == 0, out.max_open() == max_open, out.max_bytes() == max_bytes,
            out.open_requests() == Seq::<u64>::empty(),
    {
        let out = Assembler { open: Vec::new(), max_open, max_bytes };
        proof { assert(out.open_requests() =~= Seq::<u64>::empty()); }
        out
    }

    pub fn open_exchanges(&self) -> (out: usize) ensures out == self.open_count(), { self.open.len() }

    fn find(&self, request: u64) -> (out: Option<usize>)
        ensures match out {
            Some(i) => i < self.open@.len() && self.open@[i as int].request == request,
            None => !self.has_open(request),
        },
    {
        let mut i: usize = 0;
        while i < self.open.len()
            invariant i <= self.open.len(),
                forall|j: int| 0 <= j < i ==> (#[trigger] self.open@[j]).request != request,
            decreases self.open.len() - i,
        {
            if self.open[i].request == request { return Some(i); }
            i = i + 1;
        }
        None
    }

    // Remove one open exchange. Uniqueness and per-exchange validity of the
    // rest are preserved; the removed request is no longer open.
    fn take(&mut self, index: usize) -> (out: Exchange)
        requires old(self).valid(), index < old(self).open@.len(),
        ensures final(self).valid(), final(self).max_open() == old(self).max_open(),
            final(self).max_bytes() == old(self).max_bytes(),
            final(self).open_count() == old(self).open_count() - 1,
            final(self).open@ == old(self).open@.remove(index as int),
            final(self).open_requests() == old(self).open_requests().remove(index as int),
            out == old(self).open@[index as int], out.valid(old(self).max_bytes()),
            out.request_id() == old(self).open_requests()[index as int],
            !final(self).has_open(out.request_id()),
            forall|r: u64| r != out.request_id() ==> (final(self).has_open(r) == old(self).has_open(r)),
    {
        let ghost before = self.open@;
        let ghost before_requests = self.open_requests();
        let out = self.open.remove(index);
        proof {
            before.remove_ensures(index as int);
            before_requests.remove_ensures(index as int);
            assert(self.open_requests() =~= before_requests.remove(index as int));
            assert forall|i: int, j: int| 0 <= i < j < self.open@.len()
                implies (#[trigger] self.open@[i]).request != (#[trigger] self.open@[j]).request by {
                let a = if i < index { i } else { i + 1 };
                let b = if j < index { j } else { j + 1 };
                assert(self.open@[i] == before[a]); assert(self.open@[j] == before[b]);
            }
            assert forall|r: u64| r != out.request_id() implies (self.has_open(r) == old(self).has_open(r)) by {
                if old(self).has_open(r) {
                    let i = choose|i: int| 0 <= i < old(self).open@.len() && (#[trigger] old(self).open@[i]).request == r;
                    assert(i != index);
                    let k = if i < index { i } else { i - 1 };
                    assert(self.open@[k] == before[i]);
                    assert(self.has_open(r));
                }
                if self.has_open(r) {
                    let k = choose|k: int| 0 <= k < self.open@.len() && (#[trigger] self.open@[k]).request == r;
                    let i = if k < index { k } else { k + 1 };
                    assert(self.open@[k] == before[i]);
                    assert(old(self).has_open(r));
                }
            }
            if self.has_open(out.request_id()) {
                let k = choose|k: int| 0 <= k < self.open@.len() && (#[trigger] self.open@[k]).request == out.request;
                let i = if k < index { k } else { k + 1 };
                assert(self.open@[k] == before[i]);
                assert(before[i].request == before[index as int].request);
                assert(false);
            }
        }
        out
    }

    /// Emit the oldest open exchange as incomplete, for eviction at capacity or
    /// when input ends. `None` when nothing is open.
    pub fn evict_oldest(&mut self) -> (out: Option<Exchange>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).max_open() == old(self).max_open(),
            final(self).max_bytes() == old(self).max_bytes(),
            match out {
                Some(e) => e.valid(old(self).max_bytes()) && e.is_incomplete() && old(self).has_open(e.request_id())
                    && !final(self).has_open(e.request_id())
                    && (forall|r: u64| r != e.request_id() ==> (final(self).has_open(r) == old(self).has_open(r)))
                    && final(self).open_count() == old(self).open_count() - 1
                    && final(self).open_requests() == old(self).open_requests().drop_first()
                    && e.request_id() == old(self).open_requests()[0],
                None => old(self).open_count() == 0 && *final(self) == *old(self),
            },
            (final(self).open_requests(), match out { Some(e) => Some(e.request_id()), None => None })
                == step(old(self).open_requests(), old(self).max_open(), FLUSH, 0),
    {
        if self.open.len() == 0 { return None; }
        proof { assert(self.has_open(self.open@[0].request)); }
        let ghost before = self.open_requests();
        let mut out = self.take(0);
        out.incomplete = true;
        proof { assert(before.remove(0) =~= before.drop_first()); }
        Some(out)
    }

    /// Admit one scanned record. Returns an exchange when this record completes
    /// one, when it belongs to no open request (an orphan carrying just this
    /// record), or when a request start had to evict another exchange first.
    #[verifier::rlimit(80)]
    pub fn admit(&mut self, header: Header, payload: &[u8]) -> (out: Option<Exchange>)
        requires old(self).valid(), crate::framing::valid(header), header.payload == payload.len(),
        ensures final(self).valid(), final(self).max_open() == old(self).max_open(),
            final(self).max_bytes() == old(self).max_bytes(),
            match out { Some(e) => e.valid(old(self).max_bytes()), None => true },
            // Body and head records never emit an open request's exchange and never open one.
            crate::framing::body_kind(header.kind) || header.kind == 3 ==> (
                (old(self).has_open(header.request) ==> out.is_none() && final(self).has_open(header.request))
                && (!old(self).has_open(header.request) ==> match out {
                    Some(e) => e.is_orphan() && e.request_id() == header.request && e.tenant_id() == header.tenant
                        && final(self).open_count() == old(self).open_count(),
                    None => false,
                })),
            // A completion closes its request exactly once, orphan or not.
            header.kind == 4 ==> !final(self).has_open(header.request) && match out {
                Some(e) => e.request_id() == header.request && !e.is_incomplete()
                    && (e.is_orphan() == !old(self).has_open(header.request)),
                None => false,
            },
            // A request start always leaves its request open, evicting at most one exchange.
            header.kind == 2 ==> final(self).has_open(header.request)
                && (out.is_some() == (old(self).has_open(header.request) || old(self).open_count() == old(self).max_open()))
                && match out { Some(e) => e.is_incomplete(), None => true },
            // The open list and the emitted request follow the functional spec.
            (final(self).open_requests(), match out { Some(e) => Some(e.request_id()), None => None })
                == step(old(self).open_requests(), old(self).max_open(), header.kind, header.request),
    {
        let cap = self.max_bytes;
        proof { old(self).open_requests_valid(); }
        if header.kind == 2 {
            let start = metadata::decode_request_start(payload);
            let evicted = match self.find(header.request) {
                Some(index) => {
                    proof { assert(self.has_open(header.request)); self.index_unique(index as int, header.request); }
                    let mut e = self.take(index); e.incomplete = true; Some(e)
                }
                None => if self.open.len() == self.max_open { self.evict_oldest() } else { None },
            };
            let ghost mid = *self;
            assert(!mid.has_open(header.request));
            self.open.push(Exchange::open(header.tenant, header.request, start, false));
            proof {
                let last = self.open@.len() - 1;
                assert(self.open@[last].request == header.request);
                assert(self.has_open(header.request));
                assert forall|i: int, j: int| 0 <= i < j < self.open@.len()
                    implies (#[trigger] self.open@[i]).request != (#[trigger] self.open@[j]).request by {
                    assert(self.open@[i] == mid.open@[i]);
                    if j < last { assert(self.open@[j] == mid.open@[j]); }
                }
                assert(self.open_requests() =~= mid.open_requests().push(header.request));
            }
            return evicted;
        }
        match self.find(header.request) {
            Some(index) => {
                proof { assert(self.has_open(header.request)); self.index_unique(index as int, header.request); }
                if header.kind == 4 {
                    let mut e = self.take(index);
                    e.completion = metadata::decode_completion(payload);
                    return Some(e);
                }
                let ghost before = self.open@;
                let mut e = self.take(index);
                if header.kind == 3 { e.head = metadata::decode_response_head(payload); }
                else { e.append_body(header.kind == 0, payload, cap); }
                let ghost removed = self.open@;
                self.open.insert(index, e);
                proof {
                    before.remove_ensures(index as int);
                    removed.insert_ensures(index as int, e);
                    assert forall|i: int| 0 <= i < self.open@.len() implies self.open@[i].request == before[i].request
                        && (i != index ==> self.open@[i] == before[i]) by {
                        if i < index { assert(self.open@[i] == removed[i]); }
                        else if i > index { assert(self.open@[i] == removed[i - 1]); assert(removed[i - 1] == before[i]); }
                    }
                    assert(self.open@[index as int].request == header.request);
                    assert(self.has_open(header.request));
                    assert forall|i: int, j: int| 0 <= i < j < self.open@.len()
                        implies (#[trigger] self.open@[i]).request != (#[trigger] self.open@[j]).request by {}
                    assert(self.open_requests() =~= old(self).open_requests());
                }
                None
            }
            None => {
                let mut e = Exchange::open(header.tenant, header.request, None, true);
                proof { assert(e.valid(cap as nat)); }
                if header.kind == 4 { e.completion = metadata::decode_completion(payload); }
                else if header.kind == 3 { e.head = metadata::decode_response_head(payload); }
                else { e.append_body(header.kind == 0, payload, cap); }
                Some(e)
            }
        }
    }
}

}
