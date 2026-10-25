//! Verified operator-facing health rules: when the gateway reports ready, and
//! when an availability-mode request counts as an audit gap. Both are small,
//! but they are what the operator reads, so they are checked rather than
//! tested: readiness never says ready while admission is broken or, in strict
//! mode, while the log is unhealthy, and logging loss never fails readiness in
//! availability mode; a request is counted as a gap at most once, and only in
//! availability mode.
use vstd::prelude::*;

verus! {
/// What `/readyz` reports.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Readiness { Ready, AdmissionUnavailable, AuditUnavailable }

/// The readiness rule. Admission and the worker registry must be healthy in
/// every mode; the audit log must be healthy only when the policy requires it.
pub open spec fn readiness_of(admission_healthy: bool, workers_healthy: bool, requires_audit: bool, log_healthy: bool) -> Readiness {
    if !admission_healthy || !workers_healthy { Readiness::AdmissionUnavailable }
    else if requires_audit && !log_healthy { Readiness::AuditUnavailable }
    else { Readiness::Ready }
}

pub fn readiness(admission_healthy: bool, workers_healthy: bool, requires_audit: bool, log_healthy: bool) -> (out: Readiness)
    ensures out == readiness_of(admission_healthy, workers_healthy, requires_audit, log_healthy),
        // Ready means every gate the mode needs is open.
        out == Readiness::Ready ==> admission_healthy && workers_healthy && (requires_audit ==> log_healthy),
        // Availability mode stays ready through logging loss.
        !requires_audit ==> out != Readiness::AuditUnavailable,
        // Admission failure is reported in both modes, whatever the log says.
        (!admission_healthy || !workers_healthy) ==> out == Readiness::AdmissionUnavailable,
{
    if !admission_healthy || !workers_healthy { Readiness::AdmissionUnavailable }
    else if requires_audit && !log_healthy { Readiness::AuditUnavailable }
    else { Readiness::Ready }
}

/// Once-per-request audit-gap accounting. One observer lives for one request.
pub struct GapObserver { availability: bool, reported: bool }

impl GapObserver {
    pub closed spec fn availability(&self) -> bool { self.availability }
    pub closed spec fn reported(&self) -> bool { self.reported }

    pub fn new(availability: bool) -> (out: Self)
        ensures out.availability() == availability, !out.reported(),
    { GapObserver { availability, reported: false } }

    /// Record one append outcome. Returns true exactly for the first failed
    /// append of an availability-mode request, the one event the gap counter
    /// counts; every later failure of the same request returns false, and a
    /// strict-mode request never counts.
    pub fn observe(&mut self, failed: bool) -> (count: bool)
        ensures final(self).availability() == old(self).availability(),
            count == (failed && old(self).availability() && !old(self).reported()),
            final(self).reported() == (old(self).reported() || count),
    {
        let count = failed && self.availability && !self.reported;
        if count { self.reported = true; }
        count
    }
}
}
