//! Composed requested-allocation budget from the source-level inventories in
//! `docs/resource-composition.md`. The figure is conditional on the assumptions
//! listed there; it is not an allocator, kernel, or RSS theorem. Constants are
//! the documented per-owner bounds, so a changed audit must change this file.
use gateway_core::{framing::RecordFrame, journal::DurableFrame, resource::validate_limits};
use std::{mem::size_of, net::SocketAddr};
use tokio_rustls::rustls::pki_types::TrustAnchor;

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
    /// Registries, dedicated stacks, session cache, DNS jobs, configuration, queue slots, roots.
    pub instance: u64,
    pub total: u64,
}

/// Hyper server parser owners, header vector, queued output owners, trailer assembly, response head copy.
pub const PER_INBOUND_CONNECTION: u64 = 589_824 + 196_608 + 65_549 + 49_152 + 32_768;
/// Hyper client storage, metadata copies, TLS deframer/transcript/retry/queue/chain/session/plaintext
/// allowances, verifier failure diagnostics, and the DNS reply.
pub const PER_ADMITTED_EXCHANGE: u64 = 589_824 + 196_608 + 65_549 + 49_152 + 81_967
    + 196_608 + 262_228 + 196_617 + 82_194 + 131_072 + 262_238 + 32_768 + 1_835_008 + DNS_REPLY;
const DNS_REPLY: u64 = 253 + 64 * size_of::<SocketAddr>() as u64;
const DEDICATED_STACKS: u64 = 9 * 2 * 1024 * 1024; // audit worker, four DNS, four handshake threads
const SESSION_CACHE_CONTENT: u64 = 33 * 9 * 131_119;
const DNS_JOBS: u64 = 32 * DNS_REPLY;
// Canceled handshakes can retain TLS state after their request credit returns.
// Conservatively charge every job the full exchange allowance, including unused
// HTTP categories, instead of assuming its storage remains covered by R.
const HANDSHAKE_JOBS: u64 = 32 * PER_ADMITTED_EXCHANGE;
const CONFIGURATION_CONTENT: u64 = 2 * 1024 * 1024;
const POOL_SLOTS: u64 = 64; // 32 DNS plus 32 handshake registry entries
type QueueSlot = Option<(RecordFrame, tokio::sync::oneshot::Sender<Option<DurableFrame>>)>;

/// Returns `None` for limits the gateway refuses or sums that overflow `u64`.
pub fn compose(limits: Limits) -> Option<Budget> {
    if !validate_limits(limits.requests, limits.chunk_bytes) || limits.connections == 0
        || limits.connections > 65_536 || limits.queue == 0 || limits.queue > 65_536 { return None; }
    let (r, k, c, q) = (limits.requests as u64, limits.chunk_bytes as u64, limits.connections as u64, limits.queue as u64);
    let visible_payload = (r * k).checked_add(2 * r * 32_768)?
        .checked_add((c + 2 * r) * 16_384)?
        .checked_add((q + r + 1).checked_mul(k + 65)?)?
        .checked_add((r + 1) * 33)?;
    let inbound_connections = c.checked_mul(PER_INBOUND_CONNECTION)?;
    let admitted_exchanges = r.checked_mul(PER_ADMITTED_EXCHANGE)?;
    let instance = (8 * (2 * r + c + POOL_SLOTS)).checked_add(DEDICATED_STACKS)?
        .checked_add(SESSION_CACHE_CONTENT)?.checked_add(DNS_JOBS)?.checked_add(HANDSHAKE_JOBS)?.checked_add(CONFIGURATION_CONTENT)?
        .checked_add(q.checked_mul(size_of::<QueueSlot>() as u64)?)?
        .checked_add(webpki_roots::TLS_SERVER_ROOTS.len() as u64 * size_of::<TrustAnchor<'static>>() as u64)?;
    let total = visible_payload.checked_add(inbound_connections)?.checked_add(admitted_exchanges)?.checked_add(instance)?;
    Some(Budget { visible_payload, inbound_connections, admitted_exchanges, instance, total })
}

#[cfg(test)]
mod tests {
    use super::*;
    const EXAMPLE: Limits = Limits { requests: 32, chunk_bytes: 16_384, connections: 128, queue: 16 };

    #[test]
    fn documented_constants_and_example_match_resource_composition() {
        assert_eq!(size_of::<SocketAddr>(), 32);
        assert_eq!(PER_INBOUND_CONNECTION, 933_901);
        assert_eq!(PER_ADMITTED_EXCHANGE, 3_984_134);
        let budget = compose(EXAMPLE).unwrap();
        assert_eq!(budget.visible_payload, 6_574_258);
        assert_eq!(budget.inbound_connections, 128 * 933_901);
        assert_eq!(budget.admitted_exchanges, 32 * 3_984_134);
        let fixed = 8 * (64 + 128 + 64) + 18_874_368 + 38_942_343 + 73_632 + 32 * PER_ADMITTED_EXCHANGE + 2_097_152;
        let sized = 16 * size_of::<QueueSlot>() as u64
            + webpki_roots::TLS_SERVER_ROOTS.len() as u64 * size_of::<TrustAnchor<'static>>() as u64;
        assert_eq!(budget.instance, fixed + sized);
        assert!(sized < 65_536, "{sized}");
        assert_eq!(budget.total, 6_574_258 + 128 * 933_901 + 32 * 3_984_134 + fixed + sized);
        assert!((440_900_000..441_200_000).contains(&budget.total), "{}", budget.total);
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
    fn budget_is_monotone_in_each_limit() {
        let base = compose(EXAMPLE).unwrap().total;
        assert!(compose(Limits { requests: 33, ..EXAMPLE }).unwrap().total > base);
        assert!(compose(Limits { chunk_bytes: 16_385, ..EXAMPLE }).unwrap().total > base);
        assert!(compose(Limits { connections: 129, ..EXAMPLE }).unwrap().total > base);
        assert!(compose(Limits { queue: 17, ..EXAMPLE }).unwrap().total > base);
    }
}
