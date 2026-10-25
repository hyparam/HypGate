//! Verified credential state for the cloud shipper. Uploads need an enrolled,
//! unexpired gateway token; a refresh happens only inside the renewal window or
//! once after a rejected upload; a revoked service account stops the shipper for
//! good; and every retry delay is bounded.
use vstd::prelude::*;

verus! {
pub const RENEWAL_WINDOW_SECONDS: u64 = 86_400;
pub const MAX_DELAY_SECONDS: u64 = 300;

#[derive(Debug, PartialEq, Eq, Structural)]
pub enum State { Unenrolled, Enrolled { expires_at: u64 }, Stopped }

#[derive(Debug, PartialEq, Eq, Structural)]
pub enum Recovery { Refresh, Bootstrap, Stop }

pub struct Enrollment { state: State, refreshed_after_rejection: bool }

impl Enrollment {
    pub closed spec fn state(&self) -> State { self.state }
    pub closed spec fn refreshed(&self) -> bool { self.refreshed_after_rejection }
    pub open spec fn stopped(&self) -> bool { self.state() == State::Stopped }
    pub open spec fn enrolled_until(&self) -> Option<u64> {
        match self.state() { State::Enrolled { expires_at } => Some(expires_at), _ => None }
    }

    pub fn new() -> (out: Self)
        ensures out.state() == State::Unenrolled, !out.refreshed(),
    { Enrollment { state: State::Unenrolled, refreshed_after_rejection: false } }

    pub fn is_stopped(&self) -> (out: bool) ensures out == self.stopped(), { matches!(self.state, State::Stopped) }

    /// Only an unexpired enrollment may upload.
    pub fn can_upload(&self, now: u64) -> (out: bool)
        ensures out == match self.enrolled_until() { Some(expires_at) => now < expires_at, None => false },
    {
        match self.state { State::Enrolled { expires_at } => now < expires_at, _ => false }
    }

    /// Enrolled and inside the renewal window (or already expired).
    pub fn needs_refresh(&self, now: u64) -> (out: bool)
        ensures out == match self.enrolled_until() {
            Some(expires_at) => expires_at <= now + RENEWAL_WINDOW_SECONDS, None => false },
    {
        match self.state {
            State::Enrolled { expires_at } => expires_at <= now || expires_at - now <= RENEWAL_WINDOW_SECONDS,
            _ => false,
        }
    }

    pub fn needs_bootstrap(&self) -> (out: bool)
        ensures out == (self.state() == State::Unenrolled),
    { matches!(self.state, State::Unenrolled) }

    /// A token from bootstrap or refresh. Already-expired tokens are refused and
    /// leave the state unchanged. Stopped is absorbing.
    pub fn enrolled(&mut self, expires_at: u64, now: u64) -> (ok: bool)
        ensures ok == (!old(self).stopped() && now < expires_at),
            ok ==> final(self).state() == (State::Enrolled { expires_at }) && !final(self).refreshed(),
            !ok ==> *final(self) == *old(self),
    {
        if matches!(self.state, State::Stopped) || now >= expires_at { return false; }
        self.state = State::Enrolled { expires_at };
        self.refreshed_after_rejection = false;
        true
    }

    /// An upload was accepted: a later rejection may try one refresh again.
    pub fn uploaded(&mut self)
        ensures final(self).state() == old(self).state(), !final(self).refreshed(),
    { self.refreshed_after_rejection = false; }

    /// The server rejected the gateway token on an upload (401). The first
    /// rejection after a successful upload earns one refresh; a second one means
    /// the enrollment is gone and the shipper must bootstrap again.
    pub fn rejected(&mut self) -> (out: Recovery)
        ensures old(self).stopped() ==> out == Recovery::Stop && *final(self) == *old(self),
            !old(self).stopped() && !old(self).refreshed() ==> out == Recovery::Refresh
                && final(self).state() == old(self).state() && final(self).refreshed(),
            !old(self).stopped() && old(self).refreshed() ==> out == Recovery::Bootstrap
                && final(self).state() == State::Unenrolled && !final(self).refreshed(),
    {
        if matches!(self.state, State::Stopped) { return Recovery::Stop; }
        if !self.refreshed_after_rejection { self.refreshed_after_rejection = true; return Recovery::Refresh; }
        self.state = State::Unenrolled;
        self.refreshed_after_rejection = false;
        Recovery::Bootstrap
    }

    /// The refresh itself was rejected: the enrollment is gone.
    pub fn refresh_rejected(&mut self)
        ensures old(self).stopped() ==> *final(self) == *old(self),
            !old(self).stopped() ==> final(self).state() == State::Unenrolled && !final(self).refreshed(),
    {
        if matches!(self.state, State::Stopped) { return; }
        self.state = State::Unenrolled;
        self.refreshed_after_rejection = false;
    }

    /// The service token was revoked or its account disabled: permanent stop.
    pub fn revoked(&mut self)
        ensures final(self).stopped(),
    { self.state = State::Stopped; }
}

/// Delay before retrying a throttled or unavailable server (429/503): the
/// server's `Retry-After` when positive, else a fixed ladder; never more than
/// five minutes and never zero.
pub fn throttle_delay(attempt: u32, retry_after: Option<u64>) -> (out: u64)
    ensures 1 <= out <= MAX_DELAY_SECONDS,
        match retry_after { Some(s) if 1 <= s <= MAX_DELAY_SECONDS => out == s, _ => true },
{
    match retry_after {
        Some(seconds) if seconds >= 1 => if seconds > MAX_DELAY_SECONDS { MAX_DELAY_SECONDS } else { seconds },
        _ => match attempt { 0 => 30, 1 => 60, 2 => 120, _ => MAX_DELAY_SECONDS },
    }
}

/// Delay before retrying after a transport failure or a 502/504: three short
/// retries, then the throttle ladder.
pub fn transport_delay(attempt: u32) -> (out: u64)
    ensures 1 <= out <= MAX_DELAY_SECONDS, attempt < 3 ==> out == 2 * (attempt + 1),
{
    if attempt < 3 { 2 * (attempt as u64 + 1) } else { throttle_delay(attempt - 3, None) }
}
}
