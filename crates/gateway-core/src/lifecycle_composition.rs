//! Product of the production release gates. This introduces no shadow state:
//! the witnesses are actual task credits, HTTP permits, and the disk worker.
//! Rust registry identity, disjoint mutation, and destructor correspondence are
//! the explicitly audited adapters connecting these contracts to async tasks.
use vstd::prelude::*;
verus! {
#[allow(unused_imports)]
use crate::{task_credit::TaskCredit, http_worker::{WorkerRegistry, HttpPermit},
    http_connection::{ResponseRegistry, RegisteredResponse}, disk_worker::DiskWorker};

pub proof fn cleanup_before_reuse(workers: &WorkerRegistry, worker: &TaskCredit, http: &HttpPermit,
    connections: &ResponseRegistry, connection: &TaskCredit, response: &RegisteredResponse,
    background: &TaskCredit, disk: &DiskWorker)
    requires workers.valid(), connections.valid(), disk.valid(),
    ensures
        // Even a Cleaned task cannot release a still-live HTTP descendant.
        (workers.owns_permit(http) && http.index() == worker.key().slot() && http.owner() == worker.key().id())
            ==> workers.owns_task(worker) && !workers.can_release(worker),
        (connections.owns_response(response) && response.index() == connection.key().slot()
            && response.owner() == connection.key().id())
            ==> connections.owns_task(connection) && !connections.can_release_task(connection),
        // Instantiated independently for DNS and TLS, including unread replies
        // and cleanup. A request's cancellation is not a release condition.
        background.retaining() ==> !background.releasable(),
        // Queue transfer cannot reuse the active disk slot before delivery.
        disk.busy() ==> !disk.available(),
        crate::http_accounting::charged_payload(workers, connections)
            <= 2 * workers.limit() * 32768 + (connections.limit() + 2 * workers.limit()) * 16384,
{
    if workers.owns_permit(http) && http.index() == worker.key().slot() && http.owner() == worker.key().id() {
        workers.retained_permit_blocks_release(worker, http);
    }
    if connections.owns_response(response) && response.index() == connection.key().slot()
        && response.owner() == connection.key().id() {
        connections.retained_response_blocks_release(connection, response);
    }
    crate::http_accounting::http_owner_bounds(workers, connections);
}
}
