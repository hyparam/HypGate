//! Verified backend selection and credential loading. Only environment lookup is an effect.
use vstd::prelude::*;
use crate::{config_schema::Shipping, config_values as values, destination::Parts, s3::safe_exec};

verus! {
pub struct Config {
    pub authority: Vec<u8>, pub prefix: Vec<u8>, pub region: Vec<u8>,
    pub access_key: Vec<u8>, pub secret_key: Vec<u8>, pub session_token: Vec<u8>,
}
impl Config {
    pub open spec fn valid(&self) -> bool {
        values::secret_ok(self.authority@, 4096) && crate::s3::safe(self.prefix@, true)
        && self.prefix@[0] == 47 && self.prefix@.last() == 47
        && crate::s3::safe(self.region@, false) && crate::s3::safe(self.access_key@, false)
        && values::secret_ok(self.secret_key@, 512)
        && (self.session_token.len() == 0 || values::secret_ok(self.session_token@, 16384))
    }
    pub fn is_valid(&self) -> (ok: bool)
        ensures ok == self.valid(),
    {
        values::secret_ok_exec(self.authority.as_slice(), 4096) && safe_exec(self.prefix.as_slice(), true)
            && self.prefix[0] == 47 && self.prefix[self.prefix.len() - 1] == 47
            && safe_exec(self.region.as_slice(), false) && safe_exec(self.access_key.as_slice(), false)
            && values::secret_ok_exec(self.secret_key.as_slice(), 512)
            && (self.session_token.len() == 0 || values::secret_ok_exec(self.session_token.as_slice(), 16384))
    }
}
pub enum Backend { HypAware(Vec<u8>), S3(Config) }
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Error { Destination, Credential }

pub open spec fn optional_bytes(value: Option<Vec<u8>>) -> Option<Seq<u8>> {
    match value { Some(v) => Some(v@), None => None }
}
/// A stable startup environment. The adapter returns the requested variable;
/// the verified loader chooses names, validates values, and limits reads.
pub trait Secrets {
    spec fn values(&self) -> Map<Seq<u8>, Seq<u8>>;
    spec fn reads(&self) -> Seq<Seq<u8>>;
    fn read(&mut self, name: &[u8]) -> (out: Option<Vec<u8>>)
        requires values::secret_name_ok(name@),
        ensures final(self).values() == old(self).values(), final(self).reads() == old(self).reads().push(name@),
            optional_bytes(out) == (if old(self).values().contains_key(name@) { Some(old(self).values()[name@]) } else { None });
}
pub open spec fn permitted_reads(s: Shipping, before: Seq<Seq<u8>>, after: Seq<Seq<u8>>) -> bool {
    after == before || after == before.push(s.token_env@) || after == before.push(s.token_env@).push(s.s3_access_key_env@)
        || after == before.push(s.token_env@).push(s.s3_access_key_env@).push(s.s3_session_token_env@)
}
/// Select a backend and load exactly its named credentials, at most once per role.
pub fn load<S: Secrets>(s: &Shipping, parts: &Parts, secrets: &mut S) -> (out: Result<Backend, Error>)
    ensures final(secrets).values() == old(secrets).values(),
        permitted_reads(*s, old(secrets).reads(), final(secrets).reads()),
        match out {
            Ok(Backend::HypAware(token)) => s.s3_region.len() == 0 && s.s3_access_key_env.len() == 0 && s.s3_session_token_env.len() == 0
                && parts.path@ == seq![47u8]
                && values::secret_ok(token@, 512) && old(secrets).values().contains_key(s.token_env@)
                && token@ == old(secrets).values()[s.token_env@],
            Ok(Backend::S3(c)) => c.valid() && s.s3_region.len() > 0
                && c.authority@ == parts.authority@ && c.prefix@ == parts.path@ && c.region@ == s.s3_region@
                && old(secrets).values().contains_key(s.token_env@) && c.secret_key@ == old(secrets).values()[s.token_env@]
                && old(secrets).values().contains_key(s.s3_access_key_env@) && c.access_key@ == old(secrets).values()[s.s3_access_key_env@]
                && (if s.s3_session_token_env.len() == 0 { c.session_token.len() == 0 }
                    else { old(secrets).values().contains_key(s.s3_session_token_env@) && c.session_token@ == old(secrets).values()[s.s3_session_token_env@] }),
            Err(_) => true,
        },
{
    if s.s3_region.len() == 0 {
        // HypAware endpoints are origin-relative; never silently discard a configured prefix.
        if parts.path.len() != 1 || parts.path[0] != 47 { return Err(Error::Destination); }
        if s.s3_access_key_env.len() != 0 || s.s3_session_token_env.len() != 0 { return Err(Error::Credential); }
    } else {
        if !safe_exec(s.s3_region.as_slice(), false) || !safe_exec(parts.path.as_slice(), true)
            || parts.path[0] != 47 || parts.path[parts.path.len() - 1] != 47 || !values::secret_ok_exec(parts.authority.as_slice(), 4096) { return Err(Error::Destination); }
        if !values::secret_name_ok_exec(s.s3_access_key_env.as_slice()) { return Err(Error::Credential); }
        if s.s3_session_token_env.len() != 0 && !values::secret_name_ok_exec(s.s3_session_token_env.as_slice()) { return Err(Error::Credential); }
    }
    if !values::secret_name_ok_exec(s.token_env.as_slice()) { return Err(Error::Credential); }
    let raw = match secrets.read(s.token_env.as_slice()) { Some(v) => v, None => return Err(Error::Credential) };
    if !values::secret_ok_exec(raw.as_slice(), 512) { return Err(Error::Credential); }
    if s.s3_region.len() == 0 { return Ok(Backend::HypAware(raw)); }
    let access_key = match secrets.read(s.s3_access_key_env.as_slice()) { Some(v) => v, None => return Err(Error::Credential) };
    if !safe_exec(access_key.as_slice(), false) { return Err(Error::Credential); }
    let session_token = if s.s3_session_token_env.len() == 0 { Vec::new() } else {
        let token = match secrets.read(s.s3_session_token_env.as_slice()) { Some(v) => v, None => return Err(Error::Credential) };
        if !values::secret_ok_exec(token.as_slice(), 16384) { return Err(Error::Credential); }
        token
    };
    Ok(Backend::S3(Config { authority: parts.authority.clone(), prefix: parts.path.clone(), region: s.s3_region.clone(),
        access_key, secret_key: raw, session_token }))
}
} // verus!
