//! One immutable journal designation per request, established before append.
use vstd::prelude::*;
use crate::audit_receipt::{AuditReceipt, Durability};

verus! {
pub struct JournalBinding { session: Option<u128>, require_sync: bool }
impl JournalBinding {
    pub closed spec fn session(&self) -> Option<u128> { self.session }
    pub fn new() -> (out: Self)
        ensures out.session().is_none(), out.requires_sync(),
    { Self { session: None, require_sync: true } }
    pub closed spec fn requires_sync(&self) -> bool { self.require_sync }
    pub fn with_durability(durability: Durability) -> (out: Self)
        ensures out.session().is_none(), out.requires_sync() == (durability is Durable),
    { Self { session: None, require_sync: matches!(durability, Durability::Durable) } }
    pub fn accepts_durability(&self, durable: bool) -> (ok: bool)
        ensures ok == (!self.requires_sync() || durable),
    { !self.require_sync || durable }
    pub open spec fn accepts_receipt(&self, receipt: &AuditReceipt) -> bool {
        self.session() == Some(receipt.session()) && (!self.requires_sync() || receipt.durable())
    }
    pub fn bind(&mut self, session: u128) -> (ok: bool)
        ensures final(self).requires_sync() == old(self).requires_sync(),
            ok == (old(self).session().is_none() || old(self).session() == Some(session)),
            ok ==> final(self).session() == Some(session),
            old(self).session().is_some() ==> final(self).session() == old(self).session(),
            !ok ==> *final(self) == *old(self),
    {
        match self.session {
            Some(current) => current == session,
            None => { self.session = Some(session); true },
        }
    }
    pub fn matches_session(&self, session: Option<u128>) -> (ok: bool)
        ensures ok == (self.session() == session),
    { self.session == session }
    pub fn accepts(&self, receipt: &AuditReceipt) -> (ok: bool)
        ensures ok == self.accepts_receipt(receipt),
    {
        match self.session {
            Some(session) => session == receipt.session_id() && self.accepts_durability(receipt.is_durable()),
            None => false,
        }
    }
}
}
