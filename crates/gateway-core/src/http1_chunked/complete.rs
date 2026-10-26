//! Completeness of the chunked decoder. Soundness (`lemma_done_is_chunked`)
//! says a finished decoder consumed one well-formed chunked body for the bytes
//! it emitted. Completeness, `lemma_complete`, says the converse: when the
//! bytes still to come complete a well-formed chunked body, a step never
//! rejects, consumes no more than those bytes, finishes exactly when it has
//! consumed them all, and has then emitted exactly the body the encoding
//! carries. Together the decoder accepts exactly the grammar.
//!
//! The proof rests on the grammar being prefix-determined: a size line ends
//! at the first CRLF, its digit count is where the first non-hex byte is, so
//! two readings of the same bytes agree on every chunk boundary
//! (`lemma_cancel`). Each phase of the decoder then names where in the first
//! remaining element the next byte falls (`lemma_phase_progress`).
use super::*;

verus! {

/// The first element of a chunked body for `body`: a size line ending at `e`
/// that spells `n` with `hexlen` digits, followed by the empty line that ends
/// the body (`n == 0`) or by `n` data bytes, CRLF, and another chunked body.
pub open spec fn chunked_head(mid: Seq<u8>, body: Seq<u8>, e: int, n: nat, hexlen: int) -> bool {
    crate::http1_head::crlf_at(mid, e) && crate::http1_head::clean(mid.subrange(0, e)) && size_split(mid.subrange(0, e), n, hexlen)
    && if n == 0 { mid.len() == e + 4 && crate::http1_head::crlf_at(mid, e + 2) && body.len() == 0 }
       else {
           mid.len() >= e + 4 + n && n <= body.len() && mid.subrange(e + 2, e + 2 + n) == body.subrange(0, n as int)
           && crate::http1_head::crlf_at(mid, e + 2 + n) && chunked_ok(mid.skip(e + 4 + n), body.skip(n as int))
       }
}

/// Two clean lines from the start of `s`, each ended by CRLF, are the same line.
proof fn lemma_line_determined(s: Seq<u8>, e1: int, e2: int)
    requires crate::http1_head::crlf_at(s, e1), crate::http1_head::clean(s.subrange(0, e1)),
        crate::http1_head::crlf_at(s, e2), crate::http1_head::clean(s.subrange(0, e2)),
    ensures e1 == e2,
{
    if e1 < e2 { assert(s.subrange(0, e2)[e1] == s[e1]); assert(false); }
    if e2 < e1 { assert(s.subrange(0, e1)[e2] == s[e2]); assert(false); }
}

/// A size line spells one number with one digit count: the digits end at the
/// first byte that is not hex, which is the semicolon or the end of the line.
proof fn lemma_size_split_unique(line: Seq<u8>, n1: nat, h1: int, n2: nat, h2: int)
    requires size_split(line, n1, h1), size_split(line, n2, h2),
    ensures h1 == h2, n1 == n2,
{
    if h1 < h2 { assert(line.subrange(0, h2)[h1] == line[h1]); assert(is_hex(line[h1])); assert(line[h1] == SEMICOLON); assert(false); }
    if h2 < h1 { assert(line.subrange(0, h1)[h2] == line[h2]); assert(is_hex(line[h2])); assert(line[h2] == SEMICOLON); assert(false); }
}

/// A chunked body is at least the five bytes of `0` CRLF CRLF.
proof fn lemma_chunked_len(s: Seq<u8>, body: Seq<u8>)
    requires chunked_ok(s, body),
    ensures s.len() >= 5,
{
    let k = choose|k: int| 0 <= k <= s.len() && #[trigger] chunks_ok(s.subrange(0, k), body) && last_chunk_ok(s.skip(k));
    let tail = s.skip(k);
    let e = choose|e: int| #[trigger] crate::http1_head::crlf_at(tail, e) && crate::http1_head::clean(tail.subrange(0, e))
        && size_line_ok(tail.subrange(0, e), 0) && tail.len() == e + 4 && crate::http1_head::crlf_at(tail, e + 2);
    let hexlen = choose|hexlen: int| #[trigger] size_split(tail.subrange(0, e), 0, hexlen);
    assert(hexlen >= 1 && hexlen <= e);
}

/// A chunk at the front of `mid` places its size line and data in `mid`.
/// The one place `chunk_ok` is opened in this module.
proof fn lemma_chunk_front(mid: Seq<u8>, k1: int, data: Seq<u8>) -> (r: (int, int))
    requires 0 <= k1 <= mid.len(), chunk_ok(mid.subrange(0, k1), data),
    ensures crate::http1_head::crlf_at(mid, r.0), crate::http1_head::clean(mid.subrange(0, r.0)),
        size_split(mid.subrange(0, r.0), data.len(), r.1), data.len() >= 1, k1 == r.0 + 4 + data.len(),
        mid.subrange(r.0 + 2, r.0 + 2 + data.len()) == data, crate::http1_head::crlf_at(mid, r.0 + 2 + data.len()),
{
    reveal(chunk_ok);
    let c = mid.subrange(0, k1);
    let e = choose|e: int| #[trigger] crate::http1_head::crlf_at(c, e) && crate::http1_head::clean(c.subrange(0, e))
        && size_line_ok(c.subrange(0, e), data.len()) && data.len() >= 1
        && c.len() == e + 2 + data.len() + 2 && c.subrange(e + 2, e + 2 + data.len()) == data
        && crate::http1_head::crlf_at(c, e + 2 + data.len());
    let hexlen = choose|hexlen: int| #[trigger] size_split(c.subrange(0, e), data.len(), hexlen);
    assert(c.subrange(0, e) =~= mid.subrange(0, e));
    assert(mid.subrange(e + 2, e + 2 + data.len()) =~= c.subrange(e + 2, e + 2 + data.len()));
    (e, hexlen)
}

/// Every chunked body starts with a first element as `chunked_head` describes.
proof fn lemma_chunked_head(mid: Seq<u8>, body: Seq<u8>) -> (r: (int, nat, int))
    requires chunked_ok(mid, body),
    ensures chunked_head(mid, body, r.0, r.1, r.2),
{
    let k = choose|k: int| 0 <= k <= mid.len() && #[trigger] chunks_ok(mid.subrange(0, k), body) && last_chunk_ok(mid.skip(k));
    let run = mid.subrange(0, k);
    if run.len() == 0 {
        assert(body.len() == 0);
        let tail = mid.skip(k);
        assert(tail =~= mid);
        let e = choose|e: int| #[trigger] crate::http1_head::crlf_at(tail, e) && crate::http1_head::clean(tail.subrange(0, e))
            && size_line_ok(tail.subrange(0, e), 0) && tail.len() == e + 4 && crate::http1_head::crlf_at(tail, e + 2);
        let hexlen = choose|hexlen: int| #[trigger] size_split(tail.subrange(0, e), 0, hexlen);
        assert(chunked_head(mid, body, e, 0, hexlen));
        (e, 0, hexlen)
    } else {
        let (k1, n1) = choose|k1: int, n1: int| 0 < k1 <= run.len() && 0 < n1 <= body.len()
            && #[trigger] chunk_ok(run.subrange(0, k1), body.subrange(0, n1)) && chunks_ok(run.skip(k1), body.skip(n1));
        assert(run.subrange(0, k1) =~= mid.subrange(0, k1));
        let (e, hexlen) = lemma_chunk_front(mid, k1, body.subrange(0, n1));
        let n = n1 as nat;
        let after = mid.skip(k1);
        assert(after.subrange(0, k - k1) =~= run.skip(k1));
        assert(after.skip(k - k1) =~= mid.skip(k));
        assert(chunks_ok(after.subrange(0, k - k1), body.skip(n1)));
        assert(last_chunk_ok(after.skip(k - k1)));
        assert(chunked_ok(after, body.skip(n1)));
        assert(mid.skip(e + 4 + n) =~= after);
        assert(chunked_head(mid, body, e, n, hexlen));
        (e, n, hexlen)
    }
}

/// A sequence agreeing with `pre` on the first `n1` bytes and, after them, on
/// the rest of `pre`, has `pre` as a prefix.
proof fn lemma_prefix_stitch(body: Seq<u8>, pre: Seq<u8>, n1: int)
    requires 0 <= n1 <= pre.len() <= body.len(), body.subrange(0, n1) == pre.subrange(0, n1),
        body.skip(n1).subrange(0, pre.len() - n1) == pre.skip(n1),
    ensures body.subrange(0, pre.len() as int) == pre,
{
    let m = pre.len() as int;
    assert forall|i: int| 0 <= i < m implies body[i] == pre[i] by {
        if i < n1 {
            assert(body.subrange(0, n1)[i] == body[i]);
            assert(pre.subrange(0, n1)[i] == pre[i]);
        } else {
            assert(body.skip(n1).subrange(0, m - n1)[i - n1] == body[i]);
            assert(pre.skip(n1)[i - n1] == pre[i]);
        }
    }
    assert(body.subrange(0, m) =~= pre);
}

/// Chunk boundaries are determined by the bytes: a run of chunks already read
/// off the front of a chunked body is a prefix of that body's chunks, so the
/// rest is a chunked body for the rest of the data.
proof fn lemma_cancel(pre: Seq<u8>, pre_body: Seq<u8>, mid: Seq<u8>, body: Seq<u8>)
    requires chunks_ok(pre, pre_body), chunked_ok(pre + mid, body),
    ensures pre_body.len() <= body.len(), body.subrange(0, pre_body.len() as int) == pre_body,
        chunked_ok(mid, body.skip(pre_body.len() as int)),
    decreases pre.len(),
{
    if pre.len() == 0 {
        assert(pre_body.len() == 0);
        assert(pre + mid =~= mid);
        assert(body.skip(0) =~= body);
        assert(body.subrange(0, 0) =~= pre_body);
    } else {
        let (k1, n1) = choose|k1: int, n1: int| 0 < k1 <= pre.len() && 0 < n1 <= pre_body.len()
            && #[trigger] chunk_ok(pre.subrange(0, k1), pre_body.subrange(0, n1)) && chunks_ok(pre.skip(k1), pre_body.skip(n1));
        let w = pre + mid;
        let (e, n, hexlen) = lemma_chunked_head(w, body);
        assert(pre.subrange(0, k1) =~= w.subrange(0, k1));
        let (ec, hc) = lemma_chunk_front(w, k1, pre_body.subrange(0, n1));
        lemma_line_determined(w, e, ec);
        lemma_size_split_unique(w.subrange(0, e), n, hexlen, n1 as nat, hc);
        assert(n == n1);
        assert(pre_body.subrange(0, n1) == body.subrange(0, n1));
        assert(w.skip(e + 4 + n) =~= pre.skip(k1) + mid);
        lemma_cancel(pre.skip(k1), pre_body.skip(n1), mid, body.skip(n1));
        let m = pre_body.len() as int;
        assert(body.skip(n1).skip(m - n1) =~= body.skip(m));
        lemma_prefix_stitch(body, pre_body, n1);
    }
}

impl ChunkDecoder {
    /// What the first remaining element of the body says about the next byte:
    /// the current phase accepts it, the decoder is one byte from done exactly
    /// in the last phase, and a data phase has its owed bytes and CRLF ahead.
    proof fn lemma_phase_progress(&self, rest: Seq<u8>, body: Seq<u8>)
        requires self.valid(), !self.done(), !self.failed(), rest.len() >= 1, chunked_ok(self.tail() + rest, body),
        ensures self.accepts(rest[0]),
            (self.phase == Phase::LastLf) <==> rest.len() == 1,
            self.phase == Phase::Data ==> rest.len() >= self.remaining + 2,
            self.phase == Phase::LastLf ==> body.len() == 0,
    {
        let mid = self.tail() + rest;
        let (e, n, hexlen) = lemma_chunked_head(mid, body);
        let line_bytes = mid.subrange(0, e);
        let line = self.line@;
        let d = self.digits as int;
        let l = line.len() as int;
        let b = rest[0];
        match self.phase {
            Phase::Size => {
                assert(line.subrange(0, d) =~= line);
                assert forall|k: int| 0 <= k < l implies mid[k] == line[k] && is_hex(line[k]) by {
                    assert(line.subrange(0, d)[k] == line[k]);
                }
                if l > e { assert(is_hex(line[e])); assert(line[e] == CR); assert(false); }
                assert(mid[d] == b);
                if d == e {
                    assert(b == CR);
                    assert(hexlen >= 1 && hexlen <= e);
                } else {
                    assert(d < e);
                    assert(line_bytes[d] == mid[d]);
                    if d < hexlen {
                        assert(line_bytes.subrange(0, hexlen)[d] == line_bytes[d]);
                        assert(is_hex(b));
                        assert(d < MAX_SIZE_DIGITS);
                    } else if d == hexlen {
                        assert(line_bytes[hexlen] == SEMICOLON);
                        assert(hexlen >= 1);
                    } else {
                        assert(line_bytes[hexlen] == SEMICOLON);
                        assert(line_bytes[hexlen] == line[hexlen]);
                        assert(is_hex(line[hexlen]));
                        assert(false);
                    }
                }
                assert(mid.len() >= e + 4);
            }
            Phase::Ext => {
                assert forall|k: int| 0 <= k < l implies mid[k] == line[k] && !crate::http1_head::is_break(line[k]) by {
                    if k < d { assert(line.subrange(0, d)[k] == line[k]); }
                }
                if l > e { assert(line[e] == CR); assert(false); }
                assert(mid[l] == b);
                if l == e {
                    assert(b == CR);
                } else {
                    assert(l < e);
                    if hexlen < d {
                        assert(line_bytes[hexlen] == SEMICOLON);
                        assert(line_bytes[hexlen] == line[hexlen]);
                        assert(line.subrange(0, d)[hexlen] == line[hexlen]);
                        assert(is_hex(line[hexlen]));
                        assert(false);
                    }
                    if hexlen > d {
                        assert(line_bytes.subrange(0, hexlen)[d] == line_bytes[d]);
                        assert(line_bytes[d] == line[d]);
                        assert(is_hex(SEMICOLON));
                        assert(false);
                    }
                    assert(line_bytes[l] == b);
                    assert(crate::http1_head::is_value_byte(b));
                }
                assert(mid.len() >= e + 4);
            }
            Phase::SizeCr => {
                self.lemma_line_is_size_line();
                assert(mid.subrange(0, l) =~= line);
                assert(mid[l] == CR);
                if l > e { assert(line[e] == mid[e]); assert(false); }
                if l < e { assert(line_bytes[l] == mid[l]); assert(false); }
                assert(b == mid[e + 1]);
                assert(mid.len() >= e + 4);
            }
            Phase::Data => {
                self.lemma_line_is_size_line();
                assert(mid.subrange(0, l) =~= line);
                assert(mid[l] == CR);
                if l > e { assert(line[e] == mid[e]); assert(false); }
                if l < e { assert(line_bytes[l] == mid[l]); assert(false); }
                assert(line_bytes =~= line);
                let h = choose|h: int| #[trigger] size_split(line, self.size as nat, h);
                lemma_size_split_unique(line, n, hexlen, self.size as nat, h);
                assert(n == self.size);
                assert(mid.len() >= e + 4 + n);
                assert(self.tail().len() == e + 2 + self.partial@.len());
            }
            Phase::DataCr => {
                self.lemma_line_is_size_line();
                assert(mid.subrange(0, l) =~= line);
                assert(mid[l] == CR);
                if l > e { assert(line[e] == mid[e]); assert(false); }
                if l < e { assert(line_bytes[l] == mid[l]); assert(false); }
                assert(line_bytes =~= line);
                let h = choose|h: int| #[trigger] size_split(line, self.size as nat, h);
                lemma_size_split_unique(line, n, hexlen, self.size as nat, h);
                assert(n == self.size);
                assert(self.tail().len() == e + 2 + n);
                assert(b == mid[e + 2 + n]);
                assert(mid.len() >= e + 4 + n);
            }
            Phase::DataLf => {
                self.lemma_line_is_size_line();
                assert(mid.subrange(0, l) =~= line);
                assert(mid[l] == CR);
                if l > e { assert(line[e] == mid[e]); assert(false); }
                if l < e { assert(line_bytes[l] == mid[l]); assert(false); }
                assert(line_bytes =~= line);
                let h = choose|h: int| #[trigger] size_split(line, self.size as nat, h);
                lemma_size_split_unique(line, n, hexlen, self.size as nat, h);
                assert(n == self.size);
                assert(self.tail().len() == e + 3 + n);
                assert(b == mid[e + 3 + n]);
                lemma_chunked_len(mid.skip(e + 4 + n), body.skip(n as int));
                assert(mid.len() >= e + 4 + n + 5);
            }
            Phase::LastCr => {
                self.lemma_line_is_size_line();
                assert(mid.subrange(0, l) =~= line);
                assert(mid[l] == CR);
                if l > e { assert(line[e] == mid[e]); assert(false); }
                if l < e { assert(line_bytes[l] == mid[l]); assert(false); }
                assert(line_bytes =~= line);
                let h = choose|h: int| #[trigger] size_split(line, self.size as nat, h);
                lemma_size_split_unique(line, n, hexlen, self.size as nat, h);
                assert(n == 0);
                assert(self.tail().len() == e + 2);
                assert(b == mid[e + 2]);
                assert(mid.len() == e + 4);
            }
            Phase::LastLf => {
                self.lemma_line_is_size_line();
                assert(mid.subrange(0, l) =~= line);
                assert(mid[l] == CR);
                if l > e { assert(line[e] == mid[e]); assert(false); }
                if l < e { assert(line_bytes[l] == mid[l]); assert(false); }
                assert(line_bytes =~= line);
                let h = choose|h: int| #[trigger] size_split(line, self.size as nat, h);
                lemma_size_split_unique(line, n, hexlen, self.size as nat, h);
                assert(n == 0);
                assert(self.tail().len() == e + 3);
                assert(b == mid[e + 3]);
                assert(mid.len() == e + 4);
            }
            Phase::Done | Phase::Failed => { assert(false); }
        }
    }

    /// Completeness. If the bytes still to come, `rest`, complete a chunked
    /// body for `body` after what the decoder has consumed, and the input
    /// starts with the next of those bytes, then the step did not reject,
    /// consumed no more than `rest`, is done exactly when it consumed all of
    /// `rest`, and has then emitted exactly `body`.
    pub proof fn lemma_complete(before: Self, after: Self, input: Seq<u8>, out: Step, rest: Seq<u8>, body: Seq<u8>)
        requires before.valid(), !before.done(), !before.failed(), input.len() >= 1, rest.len() >= 1, input[0] == rest[0],
            Self::step_ok(before, after, input, out), chunked_ok(before.fed() + rest, body),
        ensures out != Step::Rejected, Self::consumed(out) <= rest.len(),
            after.done() <==> after.fed() == before.fed() + rest,
            after.done() ==> after.body() == body,
    {
        let pre = before.done_bytes@;
        let mid = before.tail() + rest;
        assert(before.fed() + rest =~= pre + mid);
        lemma_cancel(pre, before.done_body@, mid, body);
        let m = before.done_body@.len() as int;
        before.lemma_phase_progress(rest, body.skip(m));
        match out {
            Step::Rejected => { assert(false); }
            Step::Framing(n) => {
                assert(rest.len() >= 2);
                assert((before.fed() + input.subrange(0, 1)).len() != (before.fed() + rest).len());
            }
            Step::Data(n) => {
                assert(n <= before.remaining);
                assert(n < rest.len());
                assert((before.fed() + input.subrange(0, n as int)).len() != (before.fed() + rest).len());
            }
            Step::Done(n) => {
                assert(rest.len() == 1);
                assert(input.subrange(0, 1) =~= rest);
                assert(body.skip(m).len() == 0);
                assert(before.partial@.len() == 0);
                assert(after.body() =~= before.done_body@);
                assert(body.subrange(0, m) =~= body);
            }
        }
    }
}

}
