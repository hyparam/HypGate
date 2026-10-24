//! Conditional composition of production buffer categories. Allocation capacity,
//! queue/task lifetimes, and completeness of the snapshot remain adapter contracts.
use vstd::prelude::*;
use crate::framing::RecordFrame;
use crate::journal::DurableFrame;

verus! {
pub open spec fn byte_sum(buffers: Seq<Seq<u8>>) -> nat
    decreases buffers.len(),
{
    if buffers.len() == 0 { 0 } else {
        byte_sum(buffers.subrange(0, buffers.len() as int - 1))
            + buffers[buffers.len() as int - 1].len()
    }
}

pub open spec fn bounded(buffers: Seq<Seq<u8>>, count: nat, size: nat) -> bool {
    buffers.len() <= count
        && forall|i: int| 0 <= i < buffers.len() ==> #[trigger] buffers[i].len() <= size
}

pub proof fn bounded_sum(buffers: Seq<Seq<u8>>, count: nat, size: nat)
    requires bounded(buffers, count, size),
    ensures byte_sum(buffers) <= count * size,
    decreases buffers.len(),
{
    if buffers.len() > 0 {
        let n = buffers.len() as int - 1;
        bounded_sum(buffers.subrange(0, n), n as nat, size);
        assert(byte_sum(buffers) <= count * size) by(nonlinear_arith)
            requires byte_sum(buffers.subrange(0, n)) <= n * size,
                buffers[n].len() <= size, n + 1 <= count, size >= 0,
                byte_sum(buffers) == byte_sum(buffers.subrange(0, n)) + buffers[n].len();
    }
}

pub open spec fn frame_bytes(frames: Seq<RecordFrame>) -> Seq<Seq<u8>> {
    frames.map(|i: int, frame: RecordFrame| frame.contents())
}
pub open spec fn receipt_bytes(receipts: Seq<DurableFrame>) -> Seq<Seq<u8>> {
    receipts.map(|i: int, receipt: DurableFrame| receipt.record())
}

pub proof fn bounded_frames(frames: Seq<RecordFrame>, count: nat, chunk: nat)
    requires frames.len() <= count,
        forall|i: int| 0 <= i < frames.len() ==> #[trigger] frames[i].valid() && frames[i].payload().len() <= chunk,
    ensures bounded(frame_bytes(frames), count, chunk + 65),
{
    assert forall|i: int| 0 <= i < frames.len() implies
        #[trigger] frame_bytes(frames)[i].len() <= chunk + 65 by {
        assert(frames[i].valid());
        assert(frames[i].payload().len() <= chunk);
        assert(frame_bytes(frames)[i] == frames[i].contents());
        frames[i].canonical();
        crate::framing::encoded_header_roundtrip(frames[i].header());
    }
}

pub proof fn bounded_receipts(receipts: Seq<DurableFrame>, count: nat, chunk: nat)
    requires receipts.len() <= count,
        forall|i: int| 0 <= i < receipts.len() ==> #[trigger] receipts[i].valid() && receipts[i].payload_len() <= chunk,
    ensures bounded(receipt_bytes(receipts), count, chunk + 65),
{
    assert forall|i: int| 0 <= i < receipts.len() implies
        #[trigger] receipt_bytes(receipts)[i].len() <= chunk + 65 by {
        assert(receipts[i].valid());
        assert(receipts[i].payload_len() <= chunk);
        assert(receipt_bytes(receipts)[i] == receipts[i].record());
        receipts[i].retained_size();
    }
}

// Chunks include either a stream's retained body OR its next read buffer.
// An adapter must establish exclusive accounting when a buffer moves between
// those states. These are ghost snapshots, not additional runtime copies.
pub struct Buffers {
    pub chunks: Seq<Seq<u8>>,
    pub readers: Seq<Seq<u8>>,
    pub output_queues: Seq<Seq<u8>>,
    pub queued_log: Seq<RecordFrame>,
    pub active_log: Seq<RecordFrame>,
    pub receipts: Seq<DurableFrame>,
    pub headers: Seq<Seq<u8>>,
}
impl Buffers {
    pub open spec fn bytes(&self) -> nat {
        byte_sum(self.chunks) + byte_sum(self.readers) + byte_sum(self.output_queues)
            + byte_sum(frame_bytes(self.queued_log)) + byte_sum(frame_bytes(self.active_log))
            + byte_sum(receipt_bytes(self.receipts)) + byte_sum(self.headers)
    }
    pub open spec fn other_categories_valid(&self, requests: nat, chunk: nat, connections: nat) -> bool {
        bounded(self.chunks, requests, chunk)
            && bounded(self.readers, 2 * requests, 32768)
            // Client receivers + sender-only cleanup tails + provider queues.
            && bounded(self.output_queues, connections + 2 * requests, 16384)
            && self.active_log.len() <= 1 && self.receipts.len() <= requests
            && (forall|i: int| 0 <= i < self.active_log.len() ==> #[trigger] self.active_log[i].valid()
                && self.active_log[i].payload().len() <= chunk)
            && (forall|i: int| 0 <= i < self.receipts.len() ==> #[trigger] self.receipts[i].valid()
                && self.receipts[i].payload_len() <= chunk)
            && bounded(self.headers, requests + 1, 33)
    }
    pub open spec fn valid(&self, requests: nat, chunk: nat, connections: nat, queue: nat) -> bool {
        self.other_categories_valid(requests, chunk, connections)
            && self.queued_log.len() <= queue
            && (forall|i: int| 0 <= i < self.queued_log.len() ==> #[trigger] self.queued_log[i].valid()
                && self.queued_log[i].payload().len() <= chunk)
    }

    // Discharge queued count and frame validity from the actual production
    // queue. Binding its configured limit to K and other category snapshots
    // remain explicit premises; no queue count is supplied independently.
    pub proof fn accounted_payload_with_queue<T>(&self, requests: nat, chunk: nat, connections: nat,
        queue: &crate::frame_queue::FrameQueue<T>)
        requires self.other_categories_valid(requests, chunk, connections), queue.valid(),
            self.queued_log == queue.frames(),
            queue.payload_limit() <= chunk,
        ensures self.bytes() <= requests * chunk + 2 * requests * 32768
            + (connections + 2 * requests) * 16384 + (queue.capacity() + requests + 1) * (chunk + 65)
            + (requests + 1) * 33,
    {
        self.accounted_payload_with_encoding(requests, chunk, connections, queue, Seq::empty());
    }

    // Encoding is outside the queue's retained-frame projection until insertion.
    // This snapshot counts it explicitly while the reservation shares Q slots.
    pub open spec fn bytes_with_encoding(&self, encoding: Seq<u8>) -> nat {
        self.bytes() + encoding.len()
    }
    pub proof fn covers_encoding(&self, encoding: Seq<u8>)
        ensures self.bytes_with_encoding(encoding) == self.bytes() + encoding.len(),
            self.bytes_with_encoding(encoding) >= encoding.len(),
    {}

    pub proof fn accounted_payload_with_encoding<T>(&self, requests: nat, chunk: nat, connections: nat,
        queue: &crate::frame_queue::FrameQueue<T>, encoding: Seq<u8>)
        requires self.other_categories_valid(requests, chunk, connections), queue.valid(),
            self.queued_log == queue.frames(), queue.payload_limit() <= chunk,
            encoding.len() <= queue.payload_limit() + 65,
            !queue.reserved() ==> encoding.len() == 0,
        ensures self.bytes_with_encoding(encoding) <= requests * chunk + 2 * requests * 32768
            + (connections + 2 * requests) * 16384 + (queue.capacity() + requests + 1) * (chunk + 65)
            + (requests + 1) * 33,
    {
        queue.encoding_and_queued_bound(encoding.len());
        bounded_sum(self.chunks, requests, chunk);
        bounded_sum(self.readers, 2 * requests, 32768);
        bounded_sum(self.output_queues, connections + 2 * requests, 16384);
        bounded_frames(self.active_log, 1, chunk);
        bounded_receipts(self.receipts, requests, chunk);
        bounded_sum(frame_bytes(self.active_log), 1, chunk + 65);
        bounded_sum(receipt_bytes(self.receipts), requests, chunk + 65);
        bounded_sum(self.headers, requests + 1, 33);
        assert(queue.capacity() * (queue.payload_limit() + 65)
            <= queue.capacity() * (chunk + 65)) by(nonlinear_arith)
            requires queue.payload_limit() <= chunk;
        assert(queue.capacity() * (chunk + 65) + (chunk + 65) + requests * (chunk + 65)
            == (queue.capacity() + requests + 1) * (chunk + 65)) by(nonlinear_arith);
    }

    pub proof fn accounted_payload_with_body<T>(&self, requests: nat, chunk: nat, connections: nat,
        queue: &crate::frame_queue::FrameQueue<T>, body: &crate::framing::RecordBody)
        requires self.other_categories_valid(requests, chunk, connections), queue.valid(), queue.reserved(),
            self.queued_log == queue.frames(), queue.payload_limit() <= chunk,
            body.valid(), body.payload().len() <= queue.payload_limit(),
        ensures self.bytes_with_encoding(body.contents()) <= requests * chunk + 2 * requests * 32768
            + (connections + 2 * requests) * 16384 + (queue.capacity() + requests + 1) * (chunk + 65)
            + (requests + 1) * 33,
    {
        body.retained_size();
        self.accounted_payload_with_encoding(requests, chunk, connections, queue, body.contents());
    }

    pub proof fn accounted_payload_with_sealed_frame<T>(&self, requests: nat, chunk: nat, connections: nat,
        queue: &crate::frame_queue::FrameQueue<T>, frame: &RecordFrame)
        requires self.other_categories_valid(requests, chunk, connections), queue.valid(), queue.reserved(),
            self.queued_log == queue.frames(), queue.payload_limit() <= chunk,
            frame.valid(), frame.payload().len() <= queue.payload_limit(),
        ensures self.bytes_with_encoding(frame.contents()) <= requests * chunk + 2 * requests * 32768
            + (connections + 2 * requests) * 16384 + (queue.capacity() + requests + 1) * (chunk + 65)
            + (requests + 1) * 33,
    {
        frame.canonical();
        crate::framing::encoded_header_roundtrip(frame.header());
        self.accounted_payload_with_encoding(requests, chunk, connections, queue, frame.contents());
    }

    // Guard against accidentally dropping a category from the modeled total.
    pub proof fn covers_categories(&self)
        ensures self.bytes() >= byte_sum(self.chunks), self.bytes() >= byte_sum(self.readers),
            self.bytes() >= byte_sum(self.output_queues), self.bytes() >= byte_sum(frame_bytes(self.queued_log)),
            self.bytes() >= byte_sum(frame_bytes(self.active_log)),
            self.bytes() >= byte_sum(receipt_bytes(self.receipts)), self.bytes() >= byte_sum(self.headers),
    {}

    pub proof fn accounted_payload_bound(&self, requests: nat, chunk: nat, connections: nat, queue: nat)
        requires self.valid(requests, chunk, connections, queue),
        ensures self.bytes() <= requests * chunk + 2 * requests * 32768
            + (connections + 2 * requests) * 16384 + (queue + requests + 1) * (chunk + 65)
            + (requests + 1) * 33,
    {
        bounded_sum(self.chunks, requests, chunk);
        bounded_sum(self.readers, 2 * requests, 32768);
        bounded_sum(self.output_queues, connections + 2 * requests, 16384);
        bounded_frames(self.queued_log, queue, chunk);
        bounded_frames(self.active_log, 1, chunk);
        bounded_receipts(self.receipts, requests, chunk);
        bounded_sum(frame_bytes(self.queued_log), queue, chunk + 65);
        bounded_sum(frame_bytes(self.active_log), 1, chunk + 65);
        bounded_sum(receipt_bytes(self.receipts), requests, chunk + 65);
        bounded_sum(self.headers, requests + 1, 33);
        assert(queue * (chunk + 65) + (chunk + 65) + requests * (chunk + 65)
            == (queue + requests + 1) * (chunk + 65)) by(nonlinear_arith);
    }
}
}
