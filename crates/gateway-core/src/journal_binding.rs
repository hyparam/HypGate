//! One immutable journal designation per request, established before append.
use vstd::prelude::*;
use crate::journal::DurableFrame;

verus! {
pub struct JournalBinding { session: Option<u128> }
impl JournalBinding {
    pub closed spec fn session(&self) -> Option<u128> { self.session }
    pub fn new() -> (out: Self)
        ensures out.session().is_none(),
    { Self { session: None } }
    pub fn bind(&mut self, session: u128) -> (ok: bool)
        ensures ok == (old(self).session().is_none() || old(self).session() == Some(session)),
            ok ==> final(self).session() == Some(session),
            old(self).session().is_some() ==> final(self).session() == old(self).session(),
            !ok ==> *final(self) == *old(self),
    {
        match self.session {
            Some(current) => current == session,
            None => { self.session = Some(session); true },
        }
    }
    pub fn accepts(&self, receipt: &DurableFrame) -> (ok: bool)
        ensures ok == (self.session() == Some(receipt.session())),
    {
        match self.session {
            Some(session) => session == receipt.session_id(),
            None => false,
        }
    }
}
}
