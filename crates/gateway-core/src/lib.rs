#![forbid(unsafe_code)]
//! Synchronous verified policy and streaming operations; no network or disk I/O.
#[allow(unused_imports)]
use vstd::prelude::*;

pub mod resource;
pub mod stream;
pub mod policy;
pub mod journal;
pub mod framing;

pub mod recovery;
pub mod audit_journal;

pub mod owned_stream;
