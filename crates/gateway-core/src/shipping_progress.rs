//! Conditional liveness witnesses over the production machine, not a second
//! transition model. These routines are proof harnesses, not network adapters.
//! A successful round models a finite read ending at EOF, at most one successful
//! enrollment, and an accepted ingest. The supplied times allow a short-lived
//! credential but require it to remain unexpired until the upload decision.
use vstd::prelude::*;
use crate::shipper::{Action, Credential, Machine, Path, Reply};
use crate::batch_builder::{MAX_BYTES, MAX_ROWS};

verus! {
/// Every queued projection can be sent; progress cannot be satisfied by poison.
pub open spec fn sendable(m: &Machine) -> bool {
    forall|i: int| 0 <= i < m.queue().len() ==>
        #[trigger] m.queue()[i].body().len() <= MAX_BYTES && m.queue()[i].rows() <= MAX_ROWS
}

/// Under successful service, a nonempty queue advances after at most two
/// requests (bootstrap/refresh, then ingest), regardless of renewal-window size.
/// EOF models eventual completion of reading; no stop/revocation occurs in this
/// suffix. Actual network success and scheduling are assumptions, not proved.
pub fn successful_round(m: &mut Machine, now: u64, upload_at: u64, expires_at: u64, status: u16)
    requires old(m).valid(), !old(m).stopped(), old(m).awaiting().is_none(),
        old(m).delay() == 0, old(m).queue().len() > 0, sendable(old(m)),
        now <= upload_at < expires_at, status == 200 || status == 202,
    ensures final(m).valid(), !final(m).stopped(), final(m).awaiting().is_none(),
        final(m).resolved() > old(m).resolved(), final(m).poisoned() == old(m).poisoned(),
        final(m).queue().len() < old(m).queue().len(), sendable(final(m)), final(m).delay() == 0,
{
    m.end_of_log();
    proof { assert(m.queue()[0].body().len() <= MAX_BYTES && m.queue()[0].rows() <= MAX_ROWS); }
    let request = match m.next(now) {
        Action::Send(r) => r,
        _ => { proof { assert(false); } return; }
    };
    if request.path != Path::Ingest {
        m.reply(now, Reply { status: 200, retry_after: None, revocation: false,
            credential: Some(Credential { jwt: Vec::new(), expires_at }) });
        m.end_of_log();
        let request = match m.next(upload_at) {
            Action::Send(r) => r,
            _ => { proof { assert(false); } return; }
        };
        proof { assert(request.path == Path::Ingest); }
    }
    proof { m.valid_bounds(); }
    m.reply(upload_at, Reply { status, retry_after: None, revocation: false, credential: None });
}

/// Times and acceptance status for one successful round. Clock time may advance
/// arbitrarily between rounds; each newly issued token must survive its round.
pub struct ServiceWindow { pub now: u64, pub upload_at: u64, pub expires_at: u64, pub status: u16 }

pub open spec fn service_ok(w: ServiceWindow) -> bool {
    w.now <= w.upload_at < w.expires_at && (w.status == 200 || w.status == 202)
}

/// A finite queued workload drains under a suffix of successful rounds. Queue
/// length is a natural-number ranking function: each accepted batch strictly
/// decreases it, so renewal cannot produce an infinite non-progressing run.
/// At most one round per queued exchange is needed, with arbitrary service
/// times and token lifetimes satisfying the per-round environmental premises.
pub fn drain_successful_suffix(m: &mut Machine, service: &Vec<ServiceWindow>)
    requires old(m).valid(), !old(m).stopped(), old(m).awaiting().is_none(),
        old(m).delay() == 0, sendable(old(m)), old(m).queue().len() <= service.len(),
        forall|i: int| 0 <= i < service.len() ==> service_ok(#[trigger] service[i]),
    ensures final(m).valid(), final(m).queue().len() == 0,
        final(m).poisoned() == old(m).poisoned(),
        final(m).resolved() >= old(m).resolved(),
        old(m).queue().len() > 0 ==> final(m).resolved() > old(m).resolved(),
{
    let mut i: usize = 0;
    while m.queue_len() > 0
        invariant m.valid(), !m.stopped(), m.awaiting().is_none(), m.delay() == 0,
            sendable(m), i + m.queue().len() <= old(m).queue().len() <= service.len(),
            forall|j: int| 0 <= j < service.len() ==> service_ok(#[trigger] service[j]),
            m.poisoned() == old(m).poisoned(), m.resolved() >= old(m).resolved(),
            m.queue().len() == old(m).queue().len() || m.resolved() > old(m).resolved(),
        decreases m.queue().len(),
    {
        let w = &service[i];
        successful_round(m, w.now, w.upload_at, w.expires_at, w.status);
        i = i + 1;
    }
}
}
