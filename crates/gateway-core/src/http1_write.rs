//! Verified HTTP/1.1 head serialization. The writers produce exactly the bytes
//! the specification functions name, and the roundtrip theorems show those
//! bytes satisfy the parser's grammar for the same start line and fields: a
//! head the gateway writes is the head a conforming peer reads. The
//! preconditions are the wire conditions on names and values (token names,
//! value bytes, no surrounding blanks), which exclude line-break injection by
//! construction; `wire_ok` checks them at run time for values that did not
//! come out of the verified parser or configuration.
use vstd::prelude::*;
use crate::headers::{Field, tchar};
use crate::http1_head::{COLON, CR, LF, SP, value_byte_exec};

verus! {
/// A field as it may be written: a nonempty lowercase token name and a value
/// of value bytes with no leading or trailing blank.
pub open spec fn field_wire_ok(f: Field) -> bool {
    f.name@.len() >= 1 && (forall|k: int| 0 <= k < f.name@.len() ==> crate::headers::is_tchar(#[trigger] f.name@[k]))
        && crate::headers::lower_seq(f.name@) == f.name@
        && (forall|k: int| 0 <= k < f.value@.len() ==> crate::http1_head::is_value_byte(#[trigger] f.value@[k]))
        && (f.value@.len() == 0 || (!crate::headers::is_blank(f.value@[0]) && !crate::headers::is_blank(f.value@[f.value@.len() - 1])))
}
pub open spec fn fields_wire_ok(fields: Seq<Field>) -> bool {
    forall|i: int| 0 <= i < fields.len() ==> field_wire_ok(#[trigger] fields[i])
}
pub open spec fn method_ok(method: Seq<u8>) -> bool {
    method.len() >= 1 && forall|k: int| 0 <= k < method.len() ==> crate::headers::is_tchar(#[trigger] method[k])
}
pub open spec fn target_ok(target: Seq<u8>) -> bool {
    target.len() >= 1 && target[0] == 47 && forall|k: int| 0 <= k < target.len() ==> crate::http1_head::is_vchar(#[trigger] target[k])
}
pub open spec fn reason_ok(reason: Seq<u8>) -> bool {
    forall|k: int| 0 <= k < reason.len() ==> crate::http1_head::is_value_byte(#[trigger] reason[k])
}

/// The line for one field: `name: value` CRLF.
pub open spec fn field_line_bytes(f: Field) -> Seq<u8> { f.name@ + seq![COLON, SP] + f.value@ + seq![CR, LF] }
/// The field lines and the empty line.
pub open spec fn field_lines_bytes(fields: Seq<Field>) -> Seq<u8>
    decreases fields.len(),
{
    if fields.len() == 0 { seq![CR, LF] } else { field_line_bytes(fields[0]) + field_lines_bytes(fields.drop_first()) }
}
pub open spec fn request_line_bytes(method: Seq<u8>, target: Seq<u8>) -> Seq<u8> {
    method + seq![SP] + target + seq![SP] + crate::http1_head::version() + seq![CR, LF]
}
pub open spec fn digit_bytes(status: u16) -> Seq<u8> {
    seq![(48 + status / 100) as u8, (48 + (status / 10) % 10) as u8, (48 + status % 10) as u8]
}
pub open spec fn status_line_bytes(status: u16, reason: Seq<u8>) -> Seq<u8> {
    crate::http1_head::version() + seq![SP] + digit_bytes(status) + seq![SP] + reason + seq![CR, LF]
}
pub open spec fn request_head_bytes(method: Seq<u8>, target: Seq<u8>, fields: Seq<Field>) -> Seq<u8> {
    request_line_bytes(method, target) + field_lines_bytes(fields)
}
pub open spec fn status_head_bytes(status: u16, reason: Seq<u8>, fields: Seq<Field>) -> Seq<u8> {
    status_line_bytes(status, reason) + field_lines_bytes(fields)
}

// ---- run-time wire check ---------------------------------------------------

fn field_fits(f: &Field) -> (out: bool)
    ensures out == field_wire_ok(*f),
{
    if f.name.len() == 0 { return false; }
    let mut k: usize = 0;
    while k < f.name.len()
        invariant k <= f.name.len(),
            forall|j: int| 0 <= j < k ==> crate::headers::is_tchar(#[trigger] f.name@[j]) && crate::headers::lower_byte(f.name@[j]) == f.name@[j],
        decreases f.name.len() - k,
    {
        let b = f.name[k];
        if !tchar(b) || (b >= 65 && b <= 90) { return false; }
        k = k + 1;
    }
    proof { assert(crate::headers::lower_seq(f.name@) =~= f.name@); }
    let mut k: usize = 0;
    while k < f.value.len()
        invariant k <= f.value.len(), forall|j: int| 0 <= j < k ==> crate::http1_head::is_value_byte(#[trigger] f.value@[j]),
        decreases f.value.len() - k,
    {
        if !value_byte_exec(f.value[k]) { return false; }
        k = k + 1;
    }
    if f.value.len() > 0 {
        let first = f.value[0]; let last = f.value[f.value.len() - 1];
        if first == 32 || first == 9 || last == 32 || last == 9 { return false; }
    }
    true
}
/// Every field may be written: the precondition of the writers, checked.
pub fn wire_ok(fields: &Vec<Field>) -> (out: bool)
    ensures out == fields_wire_ok(fields@),
{
    let mut i: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(), forall|j: int| 0 <= j < i ==> field_wire_ok(#[trigger] fields@[j]),
        decreases fields.len() - i,
    {
        if !field_fits(&fields[i]) { return false; }
        i = i + 1;
    }
    true
}

// ---- writers ---------------------------------------------------------------

fn push_all(out: &mut Vec<u8>, bytes: &[u8])
    ensures final(out)@ == old(out)@ + bytes@,
{
    let mut k: usize = 0;
    while k < bytes.len()
        invariant k <= bytes.len(), out@ == old(out)@ + bytes@.subrange(0, k as int),
        decreases bytes.len() - k,
    {
        out.push(bytes[k]);
        proof { assert(old(out)@ + bytes@.subrange(0, k as int) + seq![bytes@[k as int]] =~= old(out)@ + bytes@.subrange(0, k as int + 1)); }
        k = k + 1;
    }
    proof { assert(bytes@.subrange(0, bytes@.len() as int) =~= bytes@); }
}
fn push_version(out: &mut Vec<u8>)
    ensures final(out)@ == old(out)@ + crate::http1_head::version(),
{
    out.push(72); out.push(84); out.push(84); out.push(80); out.push(47); out.push(49); out.push(46); out.push(49);
    proof { assert(out@ =~= old(out)@ + crate::http1_head::version()); }
}
fn push_crlf(out: &mut Vec<u8>)
    ensures final(out)@ == old(out)@ + seq![CR, LF],
{
    out.push(CR); out.push(LF);
    proof { assert(old(out)@.push(CR).push(LF) =~= old(out)@ + seq![CR, LF]); }
}
/// The field lines of `fields` and the empty line.
pub fn write_fields(fields: &Vec<Field>, out: &mut Vec<u8>)
    ensures final(out)@ == old(out)@ + field_lines_bytes(fields@),
{
    proof { assert(fields@.skip(0) =~= fields@); }
    let mut i: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(), out@ + field_lines_bytes(fields@.skip(i as int)) == old(out)@ + field_lines_bytes(fields@),
        decreases fields.len() - i,
    {
        let ghost before = out@;
        let f = &fields[i];
        push_all(out, f.name.as_slice());
        out.push(COLON); out.push(SP);
        push_all(out, f.value.as_slice());
        push_crlf(out);
        proof {
            assert(out@ =~= before + field_line_bytes(fields@[i as int]));
            assert(fields@.skip(i as int)[0] == fields@[i as int]);
            assert(fields@.skip(i as int).drop_first() =~= fields@.skip(i as int + 1));
            assert(field_lines_bytes(fields@.skip(i as int)) == field_line_bytes(fields@[i as int]) + field_lines_bytes(fields@.skip(i as int + 1)));
            assert(out@ + field_lines_bytes(fields@.skip(i as int + 1)) =~= before + field_lines_bytes(fields@.skip(i as int)));
        }
        i = i + 1;
    }
    push_crlf(out);
    proof { assert(fields@.skip(fields@.len() as int) =~= Seq::<Field>::empty()); }
}
/// `method SP target SP HTTP/1.1` CRLF, the field lines, and the empty line.
pub fn write_request_head(method: &[u8], target: &[u8], fields: &Vec<Field>, out: &mut Vec<u8>)
    ensures final(out)@ == old(out)@ + request_head_bytes(method@, target@, fields@),
{
    push_all(out, method); out.push(SP);
    push_all(out, target); out.push(SP);
    push_version(out);
    push_crlf(out);
    proof { assert(out@ =~= old(out)@ + request_line_bytes(method@, target@)); }
    write_fields(fields, out);
    proof { assert(out@ =~= old(out)@ + request_head_bytes(method@, target@, fields@)); }
}
/// `HTTP/1.1 SP status [SP reason]` CRLF, the field lines, and the empty line.
pub fn write_status_head(status: u16, reason: &[u8], fields: &Vec<Field>, out: &mut Vec<u8>)
    requires 100 <= status <= 599,
    ensures final(out)@ == old(out)@ + status_head_bytes(status, reason@, fields@),
{
    push_version(out); out.push(SP);
    out.push((48 + status / 100) as u8); out.push((48 + (status / 10) % 10) as u8); out.push((48 + status % 10) as u8);
    proof { assert(out@ =~= old(out)@ + crate::http1_head::version() + seq![SP] + digit_bytes(status)); }
    out.push(SP); push_all(out, reason);
    push_crlf(out);
    proof { assert(out@ =~= old(out)@ + status_line_bytes(status, reason@)); }
    write_fields(fields, out);
    proof { assert(out@ =~= old(out)@ + status_head_bytes(status, reason@, fields@)); }
}

// ---- roundtrip -------------------------------------------------------------

/// The written field lines are the block the parser's grammar names for `fields`.
pub proof fn lemma_fields_roundtrip(prefix: Seq<u8>, fields: Seq<Field>)
    requires fields_wire_ok(fields),
    ensures crate::http1_head::lines_ok(prefix + field_lines_bytes(fields), prefix.len() as int, fields),
    decreases fields.len(),
{
    let bytes = prefix + field_lines_bytes(fields);
    let start = prefix.len() as int;
    if fields.len() == 0 {
        assert(bytes[start] == CR && bytes[start + 1] == LF);
        assert(crate::http1_head::crlf_at(bytes, start));
    } else {
        let f = fields[0];
        let line = field_line_bytes(f);
        let rest = field_lines_bytes(fields.drop_first());
        let c = f.name@.len() as int;
        let e = start + line.len() - 2;
        assert(bytes =~= (prefix + line) + rest);
        assert(bytes[start] == f.name@[0]);
        assert(!crate::http1_head::crlf_at(bytes, start));
        assert(bytes[e] == CR && bytes[e + 1] == LF);
        assert(crate::http1_head::crlf_at(bytes, e));
        let sub = bytes.subrange(start, e);
        assert(sub =~= f.name@ + seq![COLON, SP] + f.value@);
        assert forall|k: int| 0 <= k < sub.len() implies !crate::http1_head::is_break(#[trigger] sub[k]) by {
            if k < c { assert(sub[k] == f.name@[k]); }
            else if k == c { assert(sub[k] == COLON); }
            else if k == c + 1 { assert(sub[k] == SP); }
            else { assert(sub[k] == f.value@[k - c - 2]); }
        }
        assert(crate::http1_head::clean(sub));
        // The field's own split: colon at c, value at [c + 2, sub.len()).
        assert(sub.subrange(0, c) =~= f.name@);
        assert(sub.subrange(c + 2, sub.len() as int) =~= f.value@);
        assert forall|k: int| c + 2 <= k < sub.len() implies crate::http1_head::is_value_byte(#[trigger] sub[k]) by {
            assert(sub[k] == f.value@[k - c - 2]);
        }
        assert(crate::http1_head::field_split(sub, f, c, c + 2, sub.len() as int));
        assert(crate::http1_head::field_line_ok(sub, f));
        // The rest of the block follows at e + 2.
        lemma_fields_roundtrip(prefix + line, fields.drop_first());
        assert((prefix + line).len() as int == e + 2);
        assert(crate::http1_head::lines_ok(bytes, e + 2, fields.drop_first()));
    }
}

/// A written request head is a request head for its start line and fields.
pub proof fn lemma_request_roundtrip(method: Seq<u8>, target: Seq<u8>, fields: Seq<Field>)
    requires method_ok(method), target_ok(target), fields_wire_ok(fields), fields.len() <= crate::headers::MAX_FIELDS,
        request_head_bytes(method, target, fields).len() <= crate::headers::MAX_BYTES,
    ensures forall|head: crate::http1_head::RequestHead| head.method@ == method && head.target@ == target && head.fields@ == fields
        ==> crate::http1_head::request_head_ok(request_head_bytes(method, target, fields), head),
{
    let line = request_line_bytes(method, target);
    let bytes = request_head_bytes(method, target, fields);
    let e = line.len() - 2;
    let a = method.len() as int;
    let b = a + 1 + target.len() as int;
    assert(bytes[e] == CR && bytes[e + 1] == LF);
    assert(crate::http1_head::crlf_at(bytes, e));
    let sub = bytes.subrange(0, e);
    assert(sub =~= method + seq![SP] + target + seq![SP] + crate::http1_head::version());
    lemma_version_bytes();
    assert forall|k: int| 0 <= k < sub.len() implies !crate::http1_head::is_break(#[trigger] sub[k]) by {
        if k < a { assert(sub[k] == method[k]); }
        else if k == a { assert(sub[k] == SP); }
        else if k < b { assert(sub[k] == target[k - a - 1]); }
        else if k == b { assert(sub[k] == SP); }
        else { assert(sub[k] == crate::http1_head::version()[k - b - 1]); }
    }
    assert(crate::http1_head::clean(sub));
    assert(sub.subrange(0, a) =~= method);
    assert(sub.subrange(a + 1, b) =~= target);
    assert(sub.subrange(b + 1, sub.len() as int) =~= crate::http1_head::version());
    assert forall|k: int| a + 1 <= k < b implies crate::http1_head::is_vchar(#[trigger] sub[k]) by { assert(sub[k] == target[k - a - 1]); }
    assert(crate::http1_head::request_line_split(sub, method, target, a, b));
    lemma_fields_roundtrip(line, fields);
    assert(bytes.len() <= crate::headers::MAX_BYTES);
    assert(crate::http1_head::fields_ok(bytes, e + 2, fields));
}

/// A written status head is a status head for its status and fields.
pub proof fn lemma_status_roundtrip(status: u16, reason: Seq<u8>, fields: Seq<Field>)
    requires 100 <= status <= 599, reason_ok(reason), fields_wire_ok(fields), fields.len() <= crate::headers::MAX_FIELDS,
        status_head_bytes(status, reason, fields).len() <= crate::headers::MAX_BYTES,
    ensures forall|head: crate::http1_head::StatusHead| head.status == status && head.fields@ == fields
        ==> crate::http1_head::status_head_ok(status_head_bytes(status, reason, fields), head),
{
    let line = status_line_bytes(status, reason);
    let bytes = status_head_bytes(status, reason, fields);
    let e = line.len() - 2;
    assert(bytes[e] == CR && bytes[e + 1] == LF);
    assert(crate::http1_head::crlf_at(bytes, e));
    let sub = bytes.subrange(0, e);
    assert(sub =~= crate::http1_head::version() + seq![SP] + digit_bytes(status) + seq![SP] + reason);
    lemma_version_bytes();
    assert forall|k: int| 0 <= k < sub.len() implies !crate::http1_head::is_break(#[trigger] sub[k]) by {
        if k < 8 { assert(sub[k] == crate::http1_head::version()[k]); }
        else if k == 8 { assert(sub[k] == SP); }
        else if k < 12 { assert(sub[k] == digit_bytes(status)[k - 9]); }
        else if k == 12 { assert(sub[k] == SP); }
        else { assert(sub[k] == reason[k - 13]); }
    }
    assert(crate::http1_head::clean(sub));
    assert(sub.subrange(0, 8) =~= crate::http1_head::version());
    assert(sub[9] == (48 + status / 100) as u8 && sub[10] == (48 + (status / 10) % 10) as u8 && sub[11] == (48 + status % 10) as u8);
    assert(status == (status / 100) * 100 + ((status / 10) % 10) * 10 + status % 10) by (nonlinear_arith) requires 100 <= status <= 599 {}
    assert forall|k: int| 13 <= k < sub.len() implies crate::http1_head::is_value_byte(#[trigger] sub[k]) by { assert(sub[k] == reason[k - 13]); }
    assert(crate::http1_head::status_line_ok(sub, status));
    lemma_fields_roundtrip(line, fields);
    assert(crate::http1_head::fields_ok(bytes, e + 2, fields));
}

/// The version bytes contain no line break.
proof fn lemma_version_bytes()
    ensures crate::http1_head::version().len() == 8, forall|k: int| 0 <= k < 8 ==> !crate::http1_head::is_break(#[trigger] crate::http1_head::version()[k]),
{}
}
