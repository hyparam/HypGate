//! Immutable detached HTTP payload. Ownership moves to Hyper on extraction.
//! Allocator rounding and dependency retention are outside logical byte bounds.
use vstd::prelude::*;
use vstd::slice::{slice_subrange, slice_to_vec};
verus! {
pub const MAX_OUTPUT_FRAME: usize = 16384;
pub open spec fn prefix_len(input: nat, requested: nat) -> nat {
    let cap = if requested < 16384 { requested } else { 16384nat };
    if input < cap { input } else { cap }
}
pub struct OutputFrame { bytes: Vec<u8> }
impl OutputFrame {
    pub closed spec fn contents(&self) -> Seq<u8> { self.bytes@ }
    pub closed spec fn valid(&self) -> bool { self.bytes.len() <= 16384 }
    pub fn copy_prefix(bytes: &[u8], requested: usize) -> (out: Self)
        ensures out.valid(),
            out.contents() == bytes@.subrange(0, prefix_len(bytes.len() as nat, requested as nat) as int),
    {
        let cap = if requested < MAX_OUTPUT_FRAME { requested } else { MAX_OUTPUT_FRAME };
        let count = if bytes.len() < cap { bytes.len() } else { cap };
        Self { bytes: slice_to_vec(slice_subrange(bytes, 0, count)) }
    }
    pub proof fn payload_bound(&self)
        requires self.valid(),
        ensures self.contents().len() <= 16384,
    {}
    pub fn len(&self) -> (out: usize)
        requires self.valid(),
        ensures out == self.contents().len(), out <= 16384,
    { self.bytes.len() }
    pub fn into_vec(self) -> (out: Vec<u8>)
        requires self.valid(),
        ensures out@ == self.contents(), out.len() <= 16384,
    { self.bytes }
}
}
