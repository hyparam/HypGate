//! SHA-256, FIPS 180-4, as a spec over byte sequences and a streaming hasher
//! proved to compute it. The spec transcribes the standard: the six logical
//! functions, the message schedule, the 64 rounds over the round constants,
//! the compression of one 512-bit block, and the padding of a message to
//! whole blocks with its bit length last. The hasher buffers a partial block,
//! compresses each whole block as it arrives, and finishes with the padded
//! tail; its digest is proved equal to the spec's hash of every byte fed.
//! That the spec is SHA-256 is checked by the tests against the standard's
//! vectors and an independent implementation.
use vstd::prelude::*;
use vstd::slice::slice_subrange;

verus! {

/// The most bytes a message may have: the standard's limit of 2^64 bits.
pub const MAX_BYTES: u64 = 0x1fff_ffff_ffff_ffff;

/// Addition modulo 2^32.
pub open spec fn add(a: u32, b: u32) -> u32 { ((a + b) % 0x1_0000_0000) as u32 }
pub open spec fn rotr(x: u32, n: u32) -> u32 recommends 0 < n < 32 { (x >> n) | (x << (32 - n)) }
pub open spec fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
pub open spec fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
pub open spec fn big0(x: u32) -> u32 { rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22) }
pub open spec fn big1(x: u32) -> u32 { rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25) }
pub open spec fn small0(x: u32) -> u32 { rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3) }
pub open spec fn small1(x: u32) -> u32 { rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10) }

/// The big-endian word at byte offset `i`.
pub open spec fn be32(b: Seq<u8>, i: int) -> u32 recommends 0 <= i, i + 4 <= b.len() {
    ((b[i] as u32) << 24) | ((b[i + 1] as u32) << 16) | ((b[i + 2] as u32) << 8) | (b[i + 3] as u32)
}
/// A word as big-endian bytes.
pub open spec fn be32_bytes(x: u32) -> Seq<u8> { seq![(x >> 24) as u8, (x >> 16) as u8, (x >> 8) as u8, x as u8] }
/// A length as eight big-endian bytes.
pub open spec fn be64(n: u64) -> Seq<u8> {
    seq![(n >> 56) as u8, (n >> 48) as u8, (n >> 40) as u8, (n >> 32) as u8, (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8]
}

/// The round constants: the first 32 bits of the fractional parts of the
/// cube roots of the first 64 primes.
pub open spec fn k(t: int) -> u32 {
    if t == 0 { 0x428a2f98 } else if t == 1 { 0x71374491 } else if t == 2 { 0xb5c0fbcf } else if t == 3 { 0xe9b5dba5 }
    else if t == 4 { 0x3956c25b } else if t == 5 { 0x59f111f1 } else if t == 6 { 0x923f82a4 } else if t == 7 { 0xab1c5ed5 }
    else if t == 8 { 0xd807aa98 } else if t == 9 { 0x12835b01 } else if t == 10 { 0x243185be } else if t == 11 { 0x550c7dc3 }
    else if t == 12 { 0x72be5d74 } else if t == 13 { 0x80deb1fe } else if t == 14 { 0x9bdc06a7 } else if t == 15 { 0xc19bf174 }
    else if t == 16 { 0xe49b69c1 } else if t == 17 { 0xefbe4786 } else if t == 18 { 0x0fc19dc6 } else if t == 19 { 0x240ca1cc }
    else if t == 20 { 0x2de92c6f } else if t == 21 { 0x4a7484aa } else if t == 22 { 0x5cb0a9dc } else if t == 23 { 0x76f988da }
    else if t == 24 { 0x983e5152 } else if t == 25 { 0xa831c66d } else if t == 26 { 0xb00327c8 } else if t == 27 { 0xbf597fc7 }
    else if t == 28 { 0xc6e00bf3 } else if t == 29 { 0xd5a79147 } else if t == 30 { 0x06ca6351 } else if t == 31 { 0x14292967 }
    else if t == 32 { 0x27b70a85 } else if t == 33 { 0x2e1b2138 } else if t == 34 { 0x4d2c6dfc } else if t == 35 { 0x53380d13 }
    else if t == 36 { 0x650a7354 } else if t == 37 { 0x766a0abb } else if t == 38 { 0x81c2c92e } else if t == 39 { 0x92722c85 }
    else if t == 40 { 0xa2bfe8a1 } else if t == 41 { 0xa81a664b } else if t == 42 { 0xc24b8b70 } else if t == 43 { 0xc76c51a3 }
    else if t == 44 { 0xd192e819 } else if t == 45 { 0xd6990624 } else if t == 46 { 0xf40e3585 } else if t == 47 { 0x106aa070 }
    else if t == 48 { 0x19a4c116 } else if t == 49 { 0x1e376c08 } else if t == 50 { 0x2748774c } else if t == 51 { 0x34b0bcb5 }
    else if t == 52 { 0x391c0cb3 } else if t == 53 { 0x4ed8aa4a } else if t == 54 { 0x5b9cca4f } else if t == 55 { 0x682e6ff3 }
    else if t == 56 { 0x748f82ee } else if t == 57 { 0x78a5636f } else if t == 58 { 0x84c87814 } else if t == 59 { 0x8cc70208 }
    else if t == 60 { 0x90befffa } else if t == 61 { 0xa4506ceb } else if t == 62 { 0xbef9a3f7 } else { 0xc67178f2 }
}

/// The eight working words.
#[derive(Clone, Copy, PartialEq, Eq, Structural, Debug)]
pub struct Words { pub a: u32, pub b: u32, pub c: u32, pub d: u32, pub e: u32, pub f: u32, pub g: u32, pub h: u32 }

/// The initial hash value: the first 32 bits of the fractional parts of the
/// square roots of the first eight primes.
pub open spec fn initial() -> Words {
    Words { a: 0x6a09e667, b: 0xbb67ae85, c: 0x3c6ef372, d: 0xa54ff53a, e: 0x510e527f, f: 0x9b05688c, g: 0x1f83d9ab, h: 0x5be0cd19 }
}

/// The message schedule word `t` of a block.
pub open spec fn schedule(block: Seq<u8>, t: int) -> u32
    decreases t,
{
    if t < 16 { be32(block, 4 * t) }
    else { add(add(add(small1(schedule(block, t - 2)), schedule(block, t - 7)), small0(schedule(block, t - 15))), schedule(block, t - 16)) }
}

/// One round.
pub open spec fn round(s: Words, kt: u32, wt: u32) -> Words {
    let t1 = add(add(add(add(s.h, big1(s.e)), ch(s.e, s.f, s.g)), kt), wt);
    let t2 = add(big0(s.a), maj(s.a, s.b, s.c));
    Words { a: add(t1, t2), b: s.a, c: s.b, d: s.c, e: add(s.d, t1), f: s.e, g: s.f, h: s.g }
}

/// The first `t` rounds over a block.
pub open spec fn rounds(s: Words, block: Seq<u8>, t: int) -> Words
    decreases t,
{
    if t <= 0 { s } else { round(rounds(s, block, t - 1), k(t - 1), schedule(block, t - 1)) }
}

/// The compression of one block into the hash value. Opaque: nothing but
/// `compress_exec` looks inside the 64 rounds.
#[verifier::opaque]
pub open spec fn compress(s: Words, block: Seq<u8>) -> Words {
    let r = rounds(s, block, 64);
    Words { a: add(s.a, r.a), b: add(s.b, r.b), c: add(s.c, r.c), d: add(s.d, r.d), e: add(s.e, r.e), f: add(s.f, r.f), g: add(s.g, r.g), h: add(s.h, r.h) }
}

/// The hash value after every whole block of `data`.
pub open spec fn chain(s: Words, data: Seq<u8>) -> Words
    decreases data.len(),
{
    if data.len() < 64 { s } else { chain(compress(s, data.take(64)), data.skip(64)) }
}

pub open spec fn zeros(n: nat) -> Seq<u8> { Seq::new(n, |i| 0u8) }
/// The zero bytes between the end marker and the length that make the
/// padded message whole blocks.
pub open spec fn pad_len(n: nat) -> nat { ((119 - n % 64) % 64) as nat }
/// The message, a one bit, zeros, and the message's bit length in 64 bits.
pub open spec fn padded(m: Seq<u8>) -> Seq<u8> recommends m.len() <= MAX_BYTES { m + seq![0x80u8] + zeros(pad_len(m.len())) + be64((8 * m.len()) as u64) }
pub open spec fn bytes_of(s: Words) -> Seq<u8> {
    be32_bytes(s.a) + be32_bytes(s.b) + be32_bytes(s.c) + be32_bytes(s.d) + be32_bytes(s.e) + be32_bytes(s.f) + be32_bytes(s.g) + be32_bytes(s.h)
}
/// SHA-256 of a message.
pub open spec fn hash(m: Seq<u8>) -> Seq<u8> { bytes_of(chain(initial(), padded(m))) }

pub proof fn lemma_padded_len(m: Seq<u8>)
    ensures padded(m).len() == m.len() + 9 + pad_len(m.len()), padded(m).len() % 64 == 0, padded(m).len() <= m.len() + 72,
{
    let n = m.len();
    let r = n % 64;
    assert(n == 64 * (n / 64) + r);
    if r <= 55 {
        assert(pad_len(n) == 55 - r);
        assert((n + 9 + (55 - r)) == 64 * (n / 64) + 64);
    } else {
        assert(pad_len(n) == 119 - r);
        assert((n + 9 + (119 - r)) == 64 * (n / 64) + 128);
    }
}

/// Whole blocks chain one after another.
pub proof fn lemma_chain_append(s: Words, a: Seq<u8>, b: Seq<u8>)
    requires a.len() % 64 == 0,
    ensures chain(s, a + b) == chain(chain(s, a), b),
    decreases a.len(),
{
    if a.len() == 0 {
        assert(a + b =~= b);
    } else {
        assert((a + b).take(64) =~= a.take(64));
        assert((a + b).skip(64) =~= a.skip(64) + b);
        lemma_chain_append(compress(s, a.take(64)), a.skip(64), b);
    }
}

fn add_exec(a: u32, b: u32) -> (out: u32)
    ensures out == add(a, b),
{
    a.wrapping_add(b)
}

fn rotr_exec(x: u32, n: u32) -> (out: u32)
    requires 0 < n < 32,
    ensures out == rotr(x, n),
{
    (x >> n) | (x << (32 - n))
}

fn k_exec(t: usize) -> (out: u32)
    requires t < 64,
    ensures out == k(t as int),
{
    if t == 0 { 0x428a2f98 } else if t == 1 { 0x71374491 } else if t == 2 { 0xb5c0fbcf } else if t == 3 { 0xe9b5dba5 }
    else if t == 4 { 0x3956c25b } else if t == 5 { 0x59f111f1 } else if t == 6 { 0x923f82a4 } else if t == 7 { 0xab1c5ed5 }
    else if t == 8 { 0xd807aa98 } else if t == 9 { 0x12835b01 } else if t == 10 { 0x243185be } else if t == 11 { 0x550c7dc3 }
    else if t == 12 { 0x72be5d74 } else if t == 13 { 0x80deb1fe } else if t == 14 { 0x9bdc06a7 } else if t == 15 { 0xc19bf174 }
    else if t == 16 { 0xe49b69c1 } else if t == 17 { 0xefbe4786 } else if t == 18 { 0x0fc19dc6 } else if t == 19 { 0x240ca1cc }
    else if t == 20 { 0x2de92c6f } else if t == 21 { 0x4a7484aa } else if t == 22 { 0x5cb0a9dc } else if t == 23 { 0x76f988da }
    else if t == 24 { 0x983e5152 } else if t == 25 { 0xa831c66d } else if t == 26 { 0xb00327c8 } else if t == 27 { 0xbf597fc7 }
    else if t == 28 { 0xc6e00bf3 } else if t == 29 { 0xd5a79147 } else if t == 30 { 0x06ca6351 } else if t == 31 { 0x14292967 }
    else if t == 32 { 0x27b70a85 } else if t == 33 { 0x2e1b2138 } else if t == 34 { 0x4d2c6dfc } else if t == 35 { 0x53380d13 }
    else if t == 36 { 0x650a7354 } else if t == 37 { 0x766a0abb } else if t == 38 { 0x81c2c92e } else if t == 39 { 0x92722c85 }
    else if t == 40 { 0xa2bfe8a1 } else if t == 41 { 0xa81a664b } else if t == 42 { 0xc24b8b70 } else if t == 43 { 0xc76c51a3 }
    else if t == 44 { 0xd192e819 } else if t == 45 { 0xd6990624 } else if t == 46 { 0xf40e3585 } else if t == 47 { 0x106aa070 }
    else if t == 48 { 0x19a4c116 } else if t == 49 { 0x1e376c08 } else if t == 50 { 0x2748774c } else if t == 51 { 0x34b0bcb5 }
    else if t == 52 { 0x391c0cb3 } else if t == 53 { 0x4ed8aa4a } else if t == 54 { 0x5b9cca4f } else if t == 55 { 0x682e6ff3 }
    else if t == 56 { 0x748f82ee } else if t == 57 { 0x78a5636f } else if t == 58 { 0x84c87814 } else if t == 59 { 0x8cc70208 }
    else if t == 60 { 0x90befffa } else if t == 61 { 0xa4506ceb } else if t == 62 { 0xbef9a3f7 } else { 0xc67178f2 }
}

/// One block compressed into the hash value.
fn compress_exec(s: Words, block: &[u8]) -> (out: Words)
    requires block.len() == 64,
    ensures out == compress(s, block@),
{
    proof { reveal(compress); }
    let mut w: Vec<u32> = Vec::new();
    let mut t: usize = 0;
    while t < 16
        invariant t <= 16, w@.len() == t, block.len() == 64, forall|j: int| 0 <= j < t ==> w@[j] == schedule(block@, j),
        decreases 16 - t,
    {
        let i = 4 * t;
        w.push(((block[i] as u32) << 24) | ((block[i + 1] as u32) << 16) | ((block[i + 2] as u32) << 8) | (block[i + 3] as u32));
        t = t + 1;
    }
    while t < 64
        invariant 16 <= t <= 64, w@.len() == t, forall|j: int| 0 <= j < t ==> w@[j] == schedule(block@, j),
        decreases 64 - t,
    {
        let s1 = rotr_exec(w[t - 2], 17) ^ rotr_exec(w[t - 2], 19) ^ (w[t - 2] >> 10);
        let s0 = rotr_exec(w[t - 15], 7) ^ rotr_exec(w[t - 15], 18) ^ (w[t - 15] >> 3);
        w.push(add_exec(add_exec(add_exec(s1, w[t - 7]), s0), w[t - 16]));
        t = t + 1;
    }
    let mut r = s;
    let mut t: usize = 0;
    while t < 64
        invariant t <= 64, w@.len() == 64, forall|j: int| 0 <= j < 64 ==> w@[j] == schedule(block@, j), r == rounds(s, block@, t as int),
        decreases 64 - t,
    {
        let b1 = rotr_exec(r.e, 6) ^ rotr_exec(r.e, 11) ^ rotr_exec(r.e, 25);
        let chv = (r.e & r.f) ^ (!r.e & r.g);
        let t1 = add_exec(add_exec(add_exec(add_exec(r.h, b1), chv), k_exec(t)), w[t]);
        let b0 = rotr_exec(r.a, 2) ^ rotr_exec(r.a, 13) ^ rotr_exec(r.a, 22);
        let majv = (r.a & r.b) ^ (r.a & r.c) ^ (r.b & r.c);
        let t2 = add_exec(b0, majv);
        r = Words { a: add_exec(t1, t2), b: r.a, c: r.b, d: r.c, e: add_exec(r.d, t1), f: r.e, g: r.f, h: r.g };
        t = t + 1;
    }
    Words { a: add_exec(s.a, r.a), b: add_exec(s.b, r.b), c: add_exec(s.c, r.c), d: add_exec(s.d, r.d),
        e: add_exec(s.e, r.e), f: add_exec(s.f, r.f), g: add_exec(s.g, r.g), h: add_exec(s.h, r.h) }
}

fn push_be32(out: &mut Vec<u8>, x: u32)
    ensures final(out)@ == old(out)@ + be32_bytes(x),
{
    out.push((x >> 24) as u8); out.push((x >> 16) as u8); out.push((x >> 8) as u8); out.push(x as u8);
    proof { assert(out@ =~= old(out)@ + be32_bytes(x)); }
}

fn push_be64(out: &mut Vec<u8>, x: u64)
    ensures final(out)@ == old(out)@ + be64(x),
{
    out.push((x >> 56) as u8); out.push((x >> 48) as u8); out.push((x >> 40) as u8); out.push((x >> 32) as u8);
    out.push((x >> 24) as u8); out.push((x >> 16) as u8); out.push((x >> 8) as u8); out.push(x as u8);
    proof { assert(out@ =~= old(out)@ + be64(x)); }
}

/// The bytes of `fed` in whole blocks.
pub open spec fn whole(fed: Seq<u8>) -> int { fed.len() - fed.len() % 64 }
/// The hasher's state for `fed`: the buffer holds the bytes after the whole
/// blocks and the words are the chain over the whole blocks.
pub open spec fn consistent(words: Words, buffer: Seq<u8>, fed: Seq<u8>) -> bool {
    buffer == fed.skip(whole(fed)) && words == chain(initial(), fed.take(whole(fed)))
}

proof fn lemma_push(words: Words, buffer: Seq<u8>, fed: Seq<u8>, byte: u8)
    requires consistent(words, buffer, fed), buffer.len() < 63,
    ensures consistent(words, buffer.push(byte), fed.push(byte)),
{
    let next = fed.push(byte);
    assert(whole(next) == whole(fed));
    assert(next.skip(whole(fed)) =~= buffer.push(byte));
    assert(next.take(whole(fed)) =~= fed.take(whole(fed)));
}

proof fn lemma_push_full(words: Words, buffer: Seq<u8>, fed: Seq<u8>, byte: u8)
    requires consistent(words, buffer, fed), buffer.len() == 63,
    ensures consistent(compress(words, buffer.push(byte)), Seq::<u8>::empty(), fed.push(byte)),
{
    let next = fed.push(byte);
    let block = buffer.push(byte);
    assert(whole(next) == whole(fed) + 64);
    assert(next.skip(whole(next)) =~= Seq::<u8>::empty());
    assert(next.take(whole(next)) =~= fed.take(whole(fed)) + block);
    lemma_chain_append(initial(), fed.take(whole(fed)), block);
    lemma_chain_one(words, block);
}

proof fn lemma_block(words: Words, fed: Seq<u8>, block: Seq<u8>)
    requires consistent(words, Seq::<u8>::empty(), fed), block.len() == 64,
    ensures consistent(compress(words, block), Seq::<u8>::empty(), fed + block),
{
    let next = fed + block;
    assert(fed.skip(whole(fed)).len() == 0);
    assert(fed.len() % 64 == 0);
    assert(whole(next) == fed.len() + 64);
    assert(next.skip(whole(next)) =~= Seq::<u8>::empty());
    assert(next.take(whole(next)) =~= next);
    assert(fed.take(whole(fed)) =~= fed);
    lemma_chain_append(initial(), fed, block);
    lemma_chain_one(words, block);
}

/// The padded tail after the whole blocks: one or two blocks.
pub open spec fn padded_tail(m: Seq<u8>) -> Seq<u8> { m.skip(whole(m)) + seq![0x80u8] + zeros(pad_len(m.len())) + be64((8 * m.len()) as u64) }

proof fn lemma_tail(m: Seq<u8>)
    requires m.len() <= MAX_BYTES,
    ensures padded_tail(m).len() == 64 || padded_tail(m).len() == 128, padded(m) == m.take(whole(m)) + padded_tail(m),
        hash(m) == bytes_of(chain(chain(initial(), m.take(whole(m))), padded_tail(m))),
{
    assert(padded(m) =~= m.take(whole(m)) + padded_tail(m));
    lemma_padded_len(m);
    lemma_chain_append(initial(), m.take(whole(m)), padded_tail(m));
}

proof fn lemma_chain_one(s: Words, t: Seq<u8>)
    requires t.len() == 64,
    ensures chain(s, t) == compress(s, t),
{
    assert(t.take(64) =~= t);
    assert(t.skip(64) =~= Seq::<u8>::empty());
    assert(chain(s, t) == chain(compress(s, t), Seq::<u8>::empty()));
    assert(chain(compress(s, t), Seq::<u8>::empty()) == compress(s, t));
}

proof fn lemma_chain_two(s: Words, t: Seq<u8>)
    requires t.len() == 128,
    ensures chain(s, t) == compress(compress(s, t.subrange(0, 64)), t.subrange(64, 128)),
{
    assert(t.take(64) =~= t.subrange(0, 64));
    assert(chain(s, t) == chain(compress(s, t.subrange(0, 64)), t.skip(64)));
    lemma_chain_one(compress(s, t.subrange(0, 64)), t.skip(64));
    assert(t.skip(64) =~= t.subrange(64, 128));
}

/// A hash in progress over the bytes fed so far.
pub struct Hasher { words: Words, buffer: Vec<u8>, length: u64, fed: Ghost<Seq<u8>> }

impl Hasher {
    /// Every byte fed so far.
    pub closed spec fn fed(&self) -> Seq<u8> { self.fed@ }
    pub closed spec fn inv(&self) -> bool {
        self.length == self.fed@.len() && self.fed@.len() <= MAX_BYTES && consistent(self.words, self.buffer@, self.fed@)
    }

    pub fn new() -> (out: Self)
        ensures out.inv(), out.fed() == Seq::<u8>::empty(),
    {
        let words = Words { a: 0x6a09e667, b: 0xbb67ae85, c: 0x3c6ef372, d: 0xa54ff53a, e: 0x510e527f, f: 0x9b05688c, g: 0x1f83d9ab, h: 0x5be0cd19 };
        let out = Hasher { words, buffer: Vec::new(), length: 0, fed: Ghost(Seq::empty()) };
        proof {
            assert(out.buffer@ =~= out.fed@.skip(0));
            assert(out.fed@.take(0) =~= Seq::<u8>::empty());
        }
        out
    }

    /// Feed more bytes.
    pub fn update(&mut self, bytes: &[u8])
        requires old(self).inv(), old(self).fed().len() + bytes.len() <= MAX_BYTES,
        ensures final(self).inv(), final(self).fed() == old(self).fed() + bytes@,
    {
        let mut i: usize = 0;
        proof { assert(old(self).fed@ + bytes@.take(0) =~= old(self).fed@); }
        while i < bytes.len()
            invariant self.inv(), i <= bytes.len(), self.fed@ == old(self).fed@ + bytes@.take(i as int), self.fed@.len() + bytes.len() - i <= MAX_BYTES,
                self.buffer@.len() < 64,
            decreases bytes.len() - i,
        {
            if self.buffer.len() == 0 && bytes.len() - i >= 64 {
                let block = slice_subrange(bytes, i, i + 64);
                proof {
                    assert(self.buffer@ =~= Seq::<u8>::empty());
                    lemma_block(self.words, self.fed@, block@);
                    assert(old(self).fed@ + bytes@.take(i + 64) =~= self.fed@ + block@);
                }
                self.words = compress_exec(self.words, block);
                self.length = self.length + 64;
                self.fed = Ghost(self.fed@ + block@);
                i = i + 64;
            } else {
                let byte = bytes[i];
                proof {
                    assert(old(self).fed@ + bytes@.take(i + 1) =~= self.fed@.push(byte));
                    if self.buffer@.len() == 63 { lemma_push_full(self.words, self.buffer@, self.fed@, byte); }
                    else { lemma_push(self.words, self.buffer@, self.fed@, byte); }
                }
                self.buffer.push(byte);
                self.length = self.length + 1;
                self.fed = Ghost(self.fed@.push(byte));
                if self.buffer.len() == 64 {
                    self.words = compress_exec(self.words, self.buffer.as_slice());
                    self.buffer.clear();
                }
                i = i + 1;
            }
        }
        proof { assert(bytes@.take(bytes.len() as int) =~= bytes@); }
    }

    /// The digest of every byte fed.
    pub fn finish(&self) -> (out: Vec<u8>)
        requires self.inv(),
        ensures out@ == hash(self.fed()), out@.len() == 32,
    {
        let ghost m = self.fed@;
        let mut tail: Vec<u8> = self.buffer.clone();
        tail.push(0x80);
        let ghost start = tail@;
        proof { assert(start =~= self.buffer@ + seq![0x80u8]); }
        let pad = (119 - (self.length % 64) as usize) % 64;
        let mut z: usize = 0;
        proof { assert(tail@ =~= start + zeros(0)); }
        while z < pad
            invariant z <= pad, tail@ == start + zeros(z as nat),
            decreases pad - z,
        {
            tail.push(0);
            proof { assert(tail@ =~= start + zeros((z + 1) as nat)); }
            z = z + 1;
        }
        push_be64(&mut tail, self.length * 8);
        proof {
            assert(tail@ =~= padded_tail(m));
            lemma_tail(m);
        }
        let mut words = self.words;
        if tail.len() == 64 {
            proof { lemma_chain_one(words, tail@); }
            words = compress_exec(words, tail.as_slice());
        } else {
            proof { lemma_chain_two(words, tail@); }
            words = compress_exec(words, slice_subrange(tail.as_slice(), 0, 64));
            words = compress_exec(words, slice_subrange(tail.as_slice(), 64, 128));
        }
        let mut out: Vec<u8> = Vec::new();
        push_be32(&mut out, words.a); push_be32(&mut out, words.b); push_be32(&mut out, words.c); push_be32(&mut out, words.d);
        push_be32(&mut out, words.e); push_be32(&mut out, words.f); push_be32(&mut out, words.g); push_be32(&mut out, words.h);
        out
    }
}

/// SHA-256 of `bytes`.
pub fn digest(bytes: &[u8]) -> (out: Vec<u8>)
    requires bytes.len() <= MAX_BYTES,
    ensures out@ == hash(bytes@), out@.len() == 32,
{
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finish()
}

} // verus!
