use vstd::prelude::*;
use vstd::bytes::*;
use vstd::slice::slice_subrange;

verus! {
pub struct Header {
    pub payload: u32,
    pub tenant: u64,
    pub request: u64,
    pub chunk: u64,
    pub direction: u8,
}
pub open spec fn valid(h: Header) -> bool { h.payload <= 1048576 && h.request != 0 && h.direction <= 1 }
pub open spec fn encoding(h: Header) -> Seq<u8> {
    seq![83u8, 71u8, 82u8, 49u8] + spec_u32_to_le_bytes(h.payload)
        + spec_u64_to_le_bytes(h.tenant) + spec_u64_to_le_bytes(h.request)
        + spec_u64_to_le_bytes(h.chunk) + seq![h.direction]
}
pub open spec fn decoded(bytes: Seq<u8>) -> Option<Header> {
    if bytes.len() != 33 || bytes[0] != 83 || bytes[1] != 71 || bytes[2] != 82 || bytes[3] != 49 {
        None
    } else {
        let h = Header { payload: spec_u32_from_le_bytes(bytes.subrange(4, 8)),
            tenant: spec_u64_from_le_bytes(bytes.subrange(8, 16)),
            request: spec_u64_from_le_bytes(bytes.subrange(16, 24)),
            chunk: spec_u64_from_le_bytes(bytes.subrange(24, 32)), direction: bytes[32] };
        if valid(h) { Some(h) } else { None }
    }
}

fn append(out: &mut Vec<u8>, bytes: &[u8])
    ensures final(out)@ == old(out)@ + bytes@,
{
    let mut i: usize = 0;
    while i < bytes.len()
        invariant i <= bytes.len(), out@ == old(out)@ + bytes@.subrange(0, i as int),
        decreases bytes.len() - i,
    {
        out.push(bytes[i]);
        i = i + 1;
        proof { assert(bytes@.subrange(0, i as int) =~= bytes@.subrange(0, i as int - 1).push(bytes@[i as int - 1])); }
    }
}

pub fn encode(h: Header) -> (out: Option<Vec<u8>>)
    ensures match out {
        Some(bytes) => valid(h) && bytes@ == encoding(h) && bytes.len() == 33 && decoded(bytes@) == Some(h),
        None => !valid(h),
    },
{
    if h.payload > 1048576 || h.request == 0 || h.direction > 1 { return None; }
    proof { lemma_auto_spec_u32_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes(); }
    let mut bytes = Vec::new();
    bytes.push(83); bytes.push(71); bytes.push(82); bytes.push(49);
    append(&mut bytes, u32_to_le_bytes(h.payload).as_slice());
    append(&mut bytes, u64_to_le_bytes(h.tenant).as_slice());
    append(&mut bytes, u64_to_le_bytes(h.request).as_slice());
    append(&mut bytes, u64_to_le_bytes(h.chunk).as_slice());
    bytes.push(h.direction);
    proof {
        assert(bytes@.subrange(4, 8) =~= spec_u32_to_le_bytes(h.payload));
        assert(bytes@.subrange(8, 16) =~= spec_u64_to_le_bytes(h.tenant));
        assert(bytes@.subrange(16, 24) =~= spec_u64_to_le_bytes(h.request));
        assert(bytes@.subrange(24, 32) =~= spec_u64_to_le_bytes(h.chunk));
    }
    Some(bytes)
}

// Frame bytes covered by the digest: canonical header followed by exact payload.
// Reserve room for the external 32-byte checksum to avoid growth in the adapter.
pub fn encode_payload(h: Header, payload: &[u8]) -> (out: Option<Vec<u8>>)
    ensures match out {
        Some(bytes) => valid(h) && h.payload == payload.len()
            && bytes@ == encoding(h) + payload@ && bytes.len() == 33 + payload.len()
            && bytes.len() <= 1048609,
        None => !valid(h) || h.payload != payload.len(),
    },
{
    if h.payload as usize != payload.len() { return None; }
    let header = match encode(h) { Some(header) => header, None => return None };
    let mut bytes = Vec::with_capacity(payload.len() + 65);
    append(&mut bytes, header.as_slice());
    append(&mut bytes, payload);
    Some(bytes)
}

// Private immutable containers keep canonical metadata and payload associated
// while trusted code computes a checksum and queues the finished frame.
pub struct RecordBody { bytes: Vec<u8>, header: Ghost<Header>, payload: Ghost<Seq<u8>> }
pub struct RecordFrame {
    bytes: Vec<u8>,
    // Erased witnesses are read only by specifications.
    #[allow(dead_code)] header: Ghost<Header>,
    #[allow(dead_code)] payload: Ghost<Seq<u8>>,
    #[allow(dead_code)] checksum: Ghost<Seq<u8>>,
}
impl RecordBody {
    pub closed spec fn header(&self) -> Header { self.header@ }
    pub closed spec fn payload(&self) -> Seq<u8> { self.payload@ }
    pub closed spec fn valid(&self) -> bool {
        valid(self.header@) && self.header@.payload == self.payload@.len()
            && self.bytes@ == encoding(self.header@) + self.payload@
    }
    pub fn new(h: Header, payload: &[u8]) -> (out: Option<Self>)
        ensures match out {
            Some(body) => body.valid() && body.header() == h && body.payload() == payload@,
            None => !valid(h) || h.payload != payload.len(),
        },
    {
        let bytes = match encode_payload(h, payload) { Some(bytes) => bytes, None => return None };
        Some(RecordBody { bytes, header: Ghost(h), payload: Ghost(payload@) })
    }
    pub fn bytes(&self) -> (out: &[u8])
        requires self.valid(),
        ensures out@ == encoding(self.header()) + self.payload(),
    { self.bytes.as_slice() }

    // Checksum computation is external; only its placement and byte identity
    // are proved. Consuming self prevents mutation after checksum calculation.
    pub fn seal(mut self, checksum: &[u8; 32]) -> (out: RecordFrame)
        requires self.valid(),
        ensures out.valid(), out.header() == self.header(), out.payload() == self.payload(),
            out.checksum() == checksum@,
    {
        append(&mut self.bytes, checksum.as_slice());
        RecordFrame { bytes: self.bytes, header: self.header, payload: self.payload,
            checksum: Ghost(checksum@) }
    }
}
impl RecordFrame {
    pub closed spec fn header(&self) -> Header { self.header@ }
    pub closed spec fn payload(&self) -> Seq<u8> { self.payload@ }
    pub closed spec fn checksum(&self) -> Seq<u8> { self.checksum@ }
    pub closed spec fn contents(&self) -> Seq<u8> { self.bytes@ }
    pub closed spec fn valid(&self) -> bool {
        valid(self.header@) && self.header@.payload == self.payload@.len()
            && self.checksum@.len() == 32
            && self.bytes@ == encoding(self.header@) + self.payload@ + self.checksum@
    }
    pub proof fn canonical(&self)
        requires self.valid(),
        ensures self.contents() == encoding(self.header()) + self.payload() + self.checksum(),
    {}
    pub fn bytes(&self) -> (out: &Vec<u8>)
        ensures out@ == self.contents(),
    { &self.bytes }
}

pub fn decode(bytes: &[u8]) -> (out: Option<Header>)
    ensures out == decoded(bytes@), match out { Some(h) => valid(h) && encoding(h) == bytes@, None => true },
{
    if bytes.len() != 33 || bytes[0] != 83 || bytes[1] != 71 || bytes[2] != 82 || bytes[3] != 49 { return None; }
    let payload = u32_from_le_bytes(slice_subrange(bytes, 4, 8));
    let tenant = u64_from_le_bytes(slice_subrange(bytes, 8, 16));
    let request = u64_from_le_bytes(slice_subrange(bytes, 16, 24));
    let chunk = u64_from_le_bytes(slice_subrange(bytes, 24, 32));
    let direction = bytes[32];
    if payload > 1048576 || request == 0 || direction > 1 { return None; }
    let h = Header { payload, tenant, request, chunk, direction };
    proof {
        lemma_auto_spec_u32_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes();
        assert(encoding(h) =~= bytes@);
    }
    Some(h)
}

// Advance only across a whole bounded frame: 33 header bytes, payload, 32 digest.
// The caller must bind available to bytes actually read; I/O is outside this core.
pub fn frame_end(start: u64, payload: u32, available: u64) -> (out: Option<u64>)
    ensures match out {
        Some(end) => payload <= 1048576 && end == start + 65 + payload && end > start
            && end - start <= available,
        None => payload > 1048576 || available < 65 + payload || start + 65 + payload > u64::MAX,
    },
{
    if payload > 1048576 { return None; }
    let length = 65u64 + payload as u64;
    if available < length || start > u64::MAX - length { return None; }
    Some(start + length)
}

// One cursor per reader. Tickets must not cross reader instances: offsets alone
// are not a global identity. The adapter owns the ticket during exact reads.
pub struct ScanTicket { start: u64 }
impl ScanTicket { pub closed spec fn start(&self) -> u64 { self.start } }
// Parsed metadata and exact owned payload admitted together by the scanner core.
pub struct RecoveredRecord { pub header: Header, pub bytes: Vec<u8> }
pub struct Cursor { offset: u64, stopped: bool }
impl Cursor {
    pub closed spec fn position(&self) -> u64 { self.offset }
    pub closed spec fn stopped(&self) -> bool { self.stopped }

    pub fn new(start: u64) -> (out: Self)
        ensures out.position() == start, !out.stopped(),
    { Cursor { offset: start, stopped: false } }

    pub fn offset(&self) -> (out: u64)
        ensures out == self.position(),
    { self.offset }

    // Default to stopped before any fallible I/O. Dropping the ticket on an
    // error or EOF leaves this cursor permanently unable to start another read.
    pub fn begin(&mut self) -> (out: Option<ScanTicket>)
        ensures final(self).position() == old(self).position(), final(self).stopped(),
            match out {
                Some(t) => !old(self).stopped() && t.start() == old(self).position(),
                None => old(self).stopped(),
            },
    {
        if self.stopped { return None; }
        self.stopped = true;
        Some(ScanTicket { start: self.offset })
    }

    // The checksum result is supplied by trusted cryptographic code. This binds
    // structural decoding, payload identity, and cursor advancement in one step.
    pub fn accept_record(&mut self, ticket: ScanTicket, header: &[u8], bytes: Vec<u8>,
        checksum_valid: bool) -> (out: Option<RecoveredRecord>)
        ensures match out {
            Some(record) => checksum_valid && decoded(header@) == Some(record.header)
                && valid(record.header) && record.header.payload == bytes.len()
                && record.bytes@ == bytes@ && old(self).stopped()
                && ticket.start() == old(self).position() && !final(self).stopped()
                && final(self).position() == old(self).position() + 65 + bytes.len(),
            None => *final(self) == *old(self) && (!checksum_valid
                || !old(self).stopped() || ticket.start() != old(self).position()
                || old(self).position() + 65 + bytes.len() > u64::MAX
                || match decoded(header@) {
                    Some(h) => h.payload != bytes.len(),
                    None => true,
                }),
        },
    {
        if !checksum_valid { return None; }
        let fields = match decode(header) { Some(fields) => fields, None => return None };
        if fields.payload as usize != bytes.len() { return None; }
        let available = 65u64 + bytes.len() as u64;
        if !self.accept(ticket, fields.payload, available) { return None; }
        Some(RecoveredRecord { header: fields, bytes })
    }

    // The caller certifies successful exact reads and checksum validation.
    // This transition proves structural extent/state accounting, not that I/O fact.
    pub fn accept(&mut self, ticket: ScanTicket, payload: u32, available: u64) -> (ok: bool)
        ensures
            ok == (old(self).stopped() && ticket.start() == old(self).position()
                && payload <= 1048576 && 65 + payload <= available
                && old(self).position() + 65 + payload <= u64::MAX),
            ok ==> old(self).stopped() && ticket.start() == old(self).position()
                && !final(self).stopped() && payload <= 1048576
                && final(self).position() == old(self).position() + 65 + payload
                && final(self).position() > old(self).position()
                && final(self).position() - old(self).position() <= available,
            !ok ==> *final(self) == *old(self),
    {
        if !self.stopped || ticket.start != self.offset { return false; }
        match frame_end(self.offset, payload, available) {
            Some(end) => { self.offset = end; self.stopped = false; true },
            None => false,
        }
    }
}

}
