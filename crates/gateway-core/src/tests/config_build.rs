//! Executable checks of the configuration assembly against a scripted secret
//! store. The proofs cover every store; these pin the concrete outcomes.
use crate::config_build::*;
use crate::config_schema::{Candidate, CredentialInput, CredentialKind, IdentityInput, Limits, Logging, Root};
use crate::policy::Route;

struct Scripted { asked: Vec<Vec<u8>>, missing: &'static [u8] }
impl Secrets for Scripted {
    fn get(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        self.asked.push(name.to_vec());
        if name == self.missing { None } else { Some([b"secret-", name].concat()) }
    }
}

fn root() -> Root {
    Root {
        identities: vec![IdentityInput { tenant: 1, sha256: vec![b'a'; 64] }, IdentityInput { tenant: 2, sha256: vec![b'b'; 64] }],
        destinations: vec![b"https://api.openai.com/v1/responses".to_vec(), b"https://[2001:db8::1]:8443/v1/messages".to_vec()],
        credentials: vec![CredentialInput { tenant: 1, kind: CredentialKind::Bearer, env: b"OPENAI_KEY".to_vec() },
            CredentialInput { tenant: 2, kind: CredentialKind::ApiKey, env: b"ANTHROPIC_KEY".to_vec() }],
        grants: vec![Route { tenant: 1, selector: 7, origin: 0, credential: 0 }, Route { tenant: 2, selector: 8, origin: 1, credential: 1 }],
        limits: Limits { requests: 2, chunk_bytes: 4096 },
        logging: Logging::Strict, durability: crate::audit_receipt::Durability::Durable,
    }
}
fn candidate() -> Candidate { Candidate { routes: root().grants } }

#[test]
fn each_credential_is_its_own_entrys_secret_in_its_own_header() {
    let mut store = Scripted { asked: Vec::new(), missing: b"" };
    let built = build(root(), candidate(), &mut store).ok().unwrap();
    assert_eq!(store.asked, vec![b"OPENAI_KEY".to_vec(), b"ANTHROPIC_KEY".to_vec()], "fetched in file order, once each");
    let [one, two] = built.credentials.as_slice() else { panic!("two credentials") };
    assert_eq!((one.tenant, one.kind, one.name.as_slice(), one.value.as_slice()), (1, CredentialKind::Bearer, &b"authorization"[..], &b"Bearer secret-OPENAI_KEY"[..]));
    assert_eq!((two.tenant, two.kind, two.name.as_slice(), two.value.as_slice()), (2, CredentialKind::ApiKey, &b"x-api-key"[..], &b"secret-ANTHROPIC_KEY"[..]));
    assert_eq!(built.destinations[1].host, b"2001:db8::1");
    assert_eq!(built.limits.chunk_bytes, 4096);
}

#[test]
fn each_refusal_names_its_cause() {
    let mut store = Scripted { asked: Vec::new(), missing: b"" };
    let mut r = root(); r.limits.requests = 0;
    assert_eq!(build(r, candidate(), &mut store).err(), Some(BuildError::Limits));
    let mut r = root(); r.identities[1].sha256[3] = b'z';
    assert_eq!(build(r, candidate(), &mut store).err(), Some(BuildError::Identity));
    let mut r = root(); r.destinations[1] = b"https://[2001:db8:zz::1]/v1".to_vec();
    assert_eq!(build(r, candidate(), &mut store).err(), Some(BuildError::Destination));
    let mut r = root(); r.credentials[0].env = b"has space".to_vec();
    assert_eq!(build(r, candidate(), &mut store).err(), Some(BuildError::Credential));
    let mut missing = Scripted { asked: Vec::new(), missing: b"ANTHROPIC_KEY" };
    assert_eq!(build(root(), candidate(), &mut missing).err(), Some(BuildError::Credential));
    let mut r = root(); r.grants[1].credential = 0;
    assert_eq!(build(r, candidate(), &mut store).err(), Some(BuildError::Policy), "tenant 2 may not use tenant 1's credential");
}
