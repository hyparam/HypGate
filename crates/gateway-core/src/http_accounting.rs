//! Counts from the actual production registries. Per-object payload bounds are
//! in read_buffer/http_message; Rust binds each permit to its physical owner.
use vstd::prelude::*;
verus! {
#[allow(unused_imports)] // These names are erased with the proof-only module.
use crate::{http_worker::{WorkerRegistry, INPUT_READER, OUTPUT_READER, UPLOAD_CHANNEL, RESPONSE_WRITER}, http_connection::ResponseRegistry};
pub open spec fn readers(workers: &WorkerRegistry) -> nat {
    crate::http_worker::role_count(workers.slots(), INPUT_READER as int) + crate::http_worker::role_count(workers.slots(), OUTPUT_READER as int)
}
pub open spec fn queues(workers: &WorkerRegistry, connections: &ResponseRegistry) -> nat {
    crate::http_connection::active_responses(connections.slots()) + crate::http_worker::role_count(workers.slots(), UPLOAD_CHANNEL as int) + crate::http_worker::role_count(workers.slots(), RESPONSE_WRITER as int)
}
pub open spec fn charged_payload(workers: &WorkerRegistry, connections: &ResponseRegistry) -> nat {
    readers(workers) * 32768 + queues(workers, connections) * 16384
}
// The client mailbox can be charged to both endpoints; that overcount is safe.
// After either endpoint dies the surviving permit still covers the mailbox.
pub proof fn http_owner_bounds(workers: &WorkerRegistry, connections: &ResponseRegistry)
    requires workers.valid(), connections.valid(),
    ensures charged_payload(workers, connections) >= crate::http_worker::role_count(workers.slots(), INPUT_READER as int) * 32768,
        charged_payload(workers, connections) >= crate::http_worker::role_count(workers.slots(), OUTPUT_READER as int) * 32768,
        charged_payload(workers, connections) >= crate::http_worker::role_count(workers.slots(), UPLOAD_CHANNEL as int) * 16384,
        charged_payload(workers, connections) >= crate::http_worker::role_count(workers.slots(), RESPONSE_WRITER as int) * 16384,
        charged_payload(workers, connections) >= crate::http_connection::active_responses(connections.slots()) * 16384,
        readers(workers) <= 2 * workers.limit(),
        queues(workers, connections) <= connections.limit() + 2 * workers.limit(),
        charged_payload(workers, connections)
            <= 2 * workers.limit() * 32768 + (connections.limit() + 2 * workers.limit()) * 16384,
{
    workers.role_count_bound(INPUT_READER as int);
    workers.role_count_bound(OUTPUT_READER as int);
    workers.role_count_bound(UPLOAD_CHANNEL as int);
    workers.role_count_bound(RESPONSE_WRITER as int);
    connections.response_count_bound();
}
}
