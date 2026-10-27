//! Composed requested-allocation budget from the source-level inventories in
//! `docs/resource-composition.md`. The figure is conditional on the assumptions
//! listed there; it is not an allocator, kernel, or RSS theorem. Constants are
//! the documented per-owner bounds, so a changed audit must change this file.
use gateway_core::{framing::RecordFrame, journal::DurableFrame, resource::validate_limits};
use std::{mem::size_of, net::SocketAddr};
use rustls::pki_types::TrustAnchor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits { pub requests: usize, pub chunk_bytes: usize, pub connections: usize, pub queue: usize }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// The verified visible payload subtotal V(R, K, C, Q).
    pub visible_payload: u64,
    /// C times the per-inbound-connection dependency allowance.
    pub inbound_connections: u64,
    /// R times the per-admitted-exchange dependency allowance.
    pub admitted_exchanges: u64,
    /// Registries, dedicated stacks, session cache, DNS replies, configuration, queue slots, roots.
    pub instance: u64,
    pub total: u64,
}

/// The connection thread's and its watcher's stacks, plus the allowances the
/// Hyper-era inventory charged a connection for parser owners, header vector,
/// queued output owners, trailer assembly, and response head copy, kept as an
/// upper bound on the codec adapter's own buffers.
pub const PER_INBOUND_CONNECTION: u64 = (crate::server::CONNECTION_STACK_BYTES + crate::server::WATCHER_STACK_BYTES) as u64
    + 589_824 + 196_608 + 65_549 + 49_152 + 32_768;
/// Client storage and metadata copies (the Hyper-era allowance, kept as an
/// upper bound), TLS deframer/transcript/retry/queue/chain/session/plaintext
/// allowances, verifier failure diagnostics, and the DNS reply.
pub const PER_ADMITTED_EXCHANGE: u64 = 589_824 + 196_608 + 65_549 + 49_152 + 81_967
    + 196_608 + 262_228 + 196_617 + 82_194 + 131_072 + 262_238 + 32_768 + 1_835_008 + DNS_REPLY;
const DNS_REPLY: u64 = 253 + 64 * size_of::<SocketAddr>() as u64;
const DEDICATED_STACKS: u64 = 5 * 2 * 1024 * 1024 + 64 * 1024; // audit worker, four DNS threads, signal thread
const SESSION_CACHE_CONTENT: u64 = 33 * 9 * 131_119;
const DNS_JOBS: u64 = 32 * DNS_REPLY;
const CONFIGURATION_CONTENT: u64 = 2 * 1024 * 1024;
const POOL_SLOTS: u64 = 32; // DNS registry entries
type ReplySlot = (Option<DurableFrame>, std::sync::mpsc::Sender<Option<DurableFrame>>);
const BATCH_DESCRIPTORS: u64 = gateway_core::batch_worker::MAX_BATCH as u64
    * (size_of::<QueueSlot>() + size_of::<ReplySlot>()) as u64;
type QueueSlot = Option<(RecordFrame, std::sync::mpsc::Sender<Option<DurableFrame>>)>;

/// Returns `None` for limits the gateway refuses or sums that overflow `u64`.
pub fn compose(limits: Limits) -> Option<Budget> {
    if !validate_limits(limits.requests, limits.chunk_bytes) || limits.connections == 0
        || limits.connections > 65_536 || limits.queue == 0 || limits.queue > 65_536 { return None; }
    let (r, k, c, q) = (limits.requests as u64, limits.chunk_bytes as u64, limits.connections as u64, limits.queue as u64);
    // The audit queue admits metadata payloads up to 8,210 bytes, so its frame
    // bound is A = max(K, 8210); the verified subtotal is instantiated at A.
    let a = k.max(gateway_core::metadata::MAX_PAYLOAD as u64);
    let visible_payload = r.checked_mul(k)?
        .checked_add(r.checked_mul(2 * 32_768)?)?
        .checked_add(c.checked_add(r.checked_mul(2)?)?.checked_mul(16_384)?)?
        .checked_add(q.checked_add(r)?.checked_add(gateway_core::batch_worker::MAX_BATCH as u64)?.checked_mul(a.checked_add(65)?)?)?
        .checked_add(r.checked_add(1)?.checked_mul(33)?)?;
    let inbound_connections = c.checked_mul(PER_INBOUND_CONNECTION)?;
    let admitted_exchanges = r.checked_mul(PER_ADMITTED_EXCHANGE)?;
    let instance = r.checked_mul(2)?.checked_add(c)?.checked_add(POOL_SLOTS)?.checked_mul(8)?.checked_add(DEDICATED_STACKS)?
        .checked_add(SESSION_CACHE_CONTENT)?.checked_add(DNS_JOBS)?.checked_add(CONFIGURATION_CONTENT)?
        .checked_add(BATCH_DESCRIPTORS)?.checked_add(q.checked_mul(size_of::<QueueSlot>() as u64)?)?
        .checked_add((webpki_roots::TLS_SERVER_ROOTS.len() as u64).checked_mul(size_of::<TrustAnchor<'static>>() as u64)?)?;
    let total = visible_payload.checked_add(inbound_connections)?.checked_add(admitted_exchanges)?.checked_add(instance)?;
    Some(Budget { visible_payload, inbound_connections, admitted_exchanges, instance, total })
}

/// Requested allocation of the optional shipper thread, in addition to the
/// gateway budget: its stack, the assembler's open exchanges, the queue of
/// projected rows it stops filling when full, one scanned record, one batch
/// under construction plus its copy in the request, and the capped reply.
pub fn shipping(open_exchanges: usize, exchange_bytes: usize) -> Option<u64> {
    if open_exchanges == 0 || open_exchanges > 65_536 || !(4_096..=16 * 1024 * 1024).contains(&exchange_bytes) { return None; }
    let (open, bytes) = (open_exchanges as u64, exchange_bytes as u64);
    let assembler = open.checked_mul(bytes)?;
    let queue = open.checked_mul(bytes.checked_add(ROW_OVERHEAD)?.checked_mul(2)?)?;
    SHIPPER_STACK.checked_add(assembler)?.checked_add(queue)?.checked_add(SCANNED_RECORD)?
        .checked_add(2 * BATCH)?.checked_add(REPLY)?.checked_add(SIGNING)
}
const SHIPPER_STACK: u64 = 2 * 1024 * 1024;
const ROW_OVERHEAD: u64 = 16 * 1024; // destination, identifiers, timestamps, usage, JSON syntax
const SCANNED_RECORD: u64 = 1024 * 1024 + 65;
const BATCH: u64 = 4 * 1024 * 1024;
const SIGNING: u64 = 128 * 1024; // S3 credentials, canonical request, HMAC and header scratch
const REPLY: u64 = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    const EXAMPLE: Limits = Limits { requests: 32, chunk_bytes: 16_384, connections: 128, queue: 16 };

    #[test]
    fn documented_constants_and_example_match_resource_composition() {
        assert_eq!(size_of::<SocketAddr>(), 32);
        assert_eq!(PER_INBOUND_CONNECTION, 589_824 + 933_901);
        assert_eq!(PER_ADMITTED_EXCHANGE, 3_984_134);
        let budget = compose(EXAMPLE).unwrap();
        assert_eq!(budget.visible_payload, 6_820_993);
        assert_eq!(budget.inbound_connections, 128 * 1_523_725);
        assert_eq!(budget.admitted_exchanges, 32 * 3_984_134);
        let fixed = BATCH_DESCRIPTORS + 8 * (64 + 128 + 32) + 10_551_296 + 38_942_343 + 73_632 + 2_097_152;
        let sized = 16 * size_of::<QueueSlot>() as u64
            + webpki_roots::TLS_SERVER_ROOTS.len() as u64 * size_of::<TrustAnchor<'static>>() as u64;
        assert_eq!(budget.instance, fixed + sized);
        assert!(sized < 65_536, "{sized}");
        assert_eq!(budget.total, 6_820_993 + 128 * 1_523_725 + 32 * 3_984_134 + fixed + sized);
        assert!((380_800_000..381_100_000).contains(&budget.total), "{}", budget.total);
    }

    #[test]
    fn refused_limits_have_no_budget_and_maximal_limits_do_not_overflow() {
        assert!(compose(Limits { requests: 0, ..EXAMPLE }).is_none());
        assert!(compose(Limits { chunk_bytes: (1 << 20) + 1, ..EXAMPLE }).is_none());
        assert!(compose(Limits { requests: 65_536, chunk_bytes: 4_096, ..EXAMPLE }).is_none()); // exceeds 128 MiB
        assert!(compose(Limits { connections: 0, ..EXAMPLE }).is_none());
        assert!(compose(Limits { connections: 65_537, ..EXAMPLE }).is_none());
        assert!(compose(Limits { queue: 0, ..EXAMPLE }).is_none());
        let maximal = compose(Limits { requests: 65_536, chunk_bytes: 2_048, connections: 65_536, queue: 65_536 }).unwrap();
        assert!(maximal.total > compose(EXAMPLE).unwrap().total);
        assert!(maximal.total < 1 << 40);
    }

    #[test]
    fn shipping_budget_matches_documented_terms_and_rejects_refused_limits() {
        assert_eq!(shipping(64, 1 << 20), Some(2_097_152 + 64 * 1_048_576 + 64 * 2 * (1_048_576 + 16_384) + 1_048_641 + 8_388_608 + 65_536 + 131_072));
        assert!(shipping(0, 1 << 20).is_none()); assert!(shipping(65_537, 1 << 20).is_none());
        assert!(shipping(1, 4_095).is_none()); assert!(shipping(1, (16 << 20) + 1).is_none());
        assert!(shipping(65_536, 16 << 20).unwrap() < 1 << 44);
        assert!(shipping(65, 1 << 20) > shipping(64, 1 << 20)); assert!(shipping(64, (1 << 20) + 1) > shipping(64, 1 << 20));
    }

    #[test]
    fn budget_is_monotone_in_each_limit() {
        let base = compose(EXAMPLE).unwrap().total;
        assert!(compose(Limits { requests: 33, ..EXAMPLE }).unwrap().total > base);
        assert!(compose(Limits { chunk_bytes: 16_385, ..EXAMPLE }).unwrap().total > base);
        assert!(compose(Limits { connections: 129, ..EXAMPLE }).unwrap().total > base);
        assert!(compose(Limits { queue: 17, ..EXAMPLE }).unwrap().total > base);
    }
}
