//! The production connection contract: safety, truthful outcomes, and positive progress.
//! This is discharged by exchange_driver::drive itself; it is not a model-only wrapper.
//! The explicit remaining joins are documented in PROOFS.md.
use vstd::prelude::*;
use crate::exchange_driver::{self as driver, Driven, Step};

verus! {
pub open spec fn succeeded(out: Driven) -> bool {
    out.outcome@.is_some() && out.outcome@.unwrap().0 == crate::metadata::OUTCOME_SUCCESS
}

/// External operations report their actual results. With no refusal, unsupported
/// input, or failed operation, a provider exchange must complete. Independently
/// of that premise, every claimed success and completion record must be truthful.
pub open spec fn connection(before: Seq<Step>, after: Seq<Step>, obstacles_before: nat,
    obstacles_after: nat, transferred: (u64, u64), out: Driven) -> bool
{
    &&& obstacles_before <= obstacles_after
    &&& after.len() > before.len()
    &&& after == before + driver::observations(out.trace@)
    &&& driver::run(out.trace@) == Some(out.progress@)
    &&& driver::client_writes(out.trace@) == out.written@
    &&& out.outcome@.is_some() == out.progress@.admitted
    &&& (out.progress@.admitted ==> out.progress@.completion.is_some())
    &&& out.closed.recorded() == (out.progress@.completion == Some(true))
    &&& (out.outcome@.is_some() ==> driver::completed_as(after, out.outcome@.unwrap(), out.closed.recorded()))
    &&& (succeeded(out) ==> out.progress@.forwarded
        && out.outcome@.unwrap().1 == transferred.0 && out.outcome@.unwrap().2 == transferred.1)
    &&& (obstacles_after == obstacles_before ==> succeeded(out) && out.progress@.forwarded && out.closed.recorded())
}

/// An admitted request cannot silently fail on a supported, successful execution.
/// The obstacle counter cannot be incremented by the core: only a trait call
/// witnessing its precisely specified failed result or unsupported input changes it.
pub proof fn unsuccessful_execution_has_observed_cause(before: Seq<Step>, after: Seq<Step>,
    obstacles_before: nat, obstacles_after: nat, transferred: (u64, u64), out: Driven)
    requires connection(before, after, obstacles_before, obstacles_after, transferred, out),
        !succeeded(out) || !out.closed.recorded(),
    ensures obstacles_after > obstacles_before,
{}

/// A successful completion record carries both counts from the actual body-copy
/// results, not caller-chosen counters. Its append is observable in the effect history.
pub proof fn recorded_success_is_exact(before: Seq<Step>, after: Seq<Step>,
    obstacles_before: nat, obstacles_after: nat, transferred: (u64, u64), out: Driven)
    requires connection(before, after, obstacles_before, obstacles_after, transferred, out),
        succeeded(out), out.closed.recorded(),
    ensures after.len() > before.len(), after.last() is Completion,
        crate::metadata::decoded_completion(after.last()->Completion_0).is_some(),
        crate::metadata::decoded_completion(after.last()->Completion_0).unwrap().1 == crate::metadata::OUTCOME_SUCCESS,
        crate::metadata::decoded_completion(after.last()->Completion_0).unwrap().2 == transferred.0,
        crate::metadata::decoded_completion(after.last()->Completion_0).unwrap().3 == transferred.1,
{

}
proof fn framing_field_is_writable(field: crate::headers::Field)
    requires crate::http1_exchange::is_close(field) || crate::http1_exchange::is_chunked(field)
        || crate::http1_exchange::is_length(field, 0),
    ensures crate::http1_write::field_wire_ok(field),
{
    reveal(crate::http1_exchange::CONNECTION); reveal(crate::http1_exchange::CONTENT_LENGTH);
    reveal(crate::http1_exchange::TRANSFER_ENCODING); reveal(crate::http1_exchange::CLOSE); reveal(crate::http1_exchange::CHUNKED);
    assert(crate::http1_exchange::CONNECTION@ =~= seq![99u8, 111u8, 110u8, 110u8, 101u8, 99u8, 116u8, 105u8, 111u8, 110u8]);
    assert(crate::http1_exchange::TRANSFER_ENCODING@ =~= seq![116u8, 114u8, 97u8, 110u8, 115u8, 102u8, 101u8, 114u8, 45u8, 101u8, 110u8, 99u8, 111u8, 100u8, 105u8, 110u8, 103u8]);
    assert(crate::http1_exchange::CONTENT_LENGTH@ =~= seq![99u8, 111u8, 110u8, 116u8, 101u8, 110u8, 116u8, 45u8, 108u8, 101u8, 110u8, 103u8, 116u8, 104u8]);
    assert forall|k: int| 0 <= k < field.name@.len() implies crate::headers::lower_byte(field.name@[k]) == field.name@[k] by {
        if crate::http1_exchange::is_close(field) { assert(field.name@ == crate::http1_exchange::CONNECTION@); }
        else if crate::http1_exchange::is_chunked(field) { assert(field.name@ == crate::http1_exchange::TRANSFER_ENCODING@); }
        else { assert(field.name@ == crate::http1_exchange::CONTENT_LENGTH@); }
    }

    assert(crate::headers::lower_seq(field.name@) =~= field.name@);
    assert forall|k: int| 0 <= k < field.name@.len() implies crate::headers::is_tchar(#[trigger] field.name@[k]) by {}
    assert forall|k: int| 0 <= k < field.value@.len() implies crate::http1_head::is_value_byte(#[trigger] field.value@[k]) by {}
}

/// Non-vacuity: every final HTTP status has a supported response with no provider
/// headers, for every valid reason phrase within the documented reason bound.
#[verifier::rlimit(100)]
pub proof fn empty_final_response_is_supported(head: crate::http1_head::StatusHead)
    requires 200 <= head.status <= 599, head.fields@.len() == 0,
    ensures driver::supported_response(head),
{
    use crate::http1_exchange as http;
    use crate::http1_write as wire;
    use crate::headers;
    assert(head.fields@ =~= Seq::<headers::Field>::empty());
    reveal(Seq::filter);
    assert(!crate::http1_framing::framing_spec_refused(head.fields@));
    assert forall|fields: Seq<headers::Field>, reason: Seq<u8>| #[trigger] headers::response_head_ok(head.fields@, fields)
        && #[trigger] wire::reason_ok(reason) && reason.len() <= 32 implies
        if head.status == 204 || head.status == 304 { http::fixed_supported(head.status, reason, fields, 0) }
        else { http::stream_supported(head.status, reason, fields) } by {
        assert(fields.len() == 0);
        assert(fields =~= Seq::<headers::Field>::empty());
        assert forall|all: Seq<headers::Field>| http::fixed_head_fields_ok(all, fields, head.status, 0)
            implies http::writable_response(head.status, reason, all) by {
            assert(all.len() <= 2);
            assert forall|i: int| 0 <= i < all.len() implies wire::field_wire_ok(#[trigger] all[i]) by {
                if i == 0 { assert(http::is_close(all[i])); }
                else { assert(http::is_length(all[i], 0)); }
                framing_field_is_writable(all[i]);
            }
            reveal_with_fuel(wire::field_lines_bytes, 3);
        }
        assert forall|all: Seq<headers::Field>| http::head_fields_ok(all, fields, true, 0)
            implies http::writable_response(head.status, reason, all) by {
            assert(all.len() == 2);
            assert forall|i: int| 0 <= i < all.len() implies wire::field_wire_ok(#[trigger] all[i]) by {
                if i == 0 { assert(http::is_close(all[i])); }
                else { assert(http::is_chunked(all[i])); }
                framing_field_is_writable(all[i]);
            }
            reveal_with_fuel(wire::field_lines_bytes, 3);
        }
    }
}

/// The progress premise includes an entire family of real POST requests.
pub proof fn empty_post_is_supported(head: crate::http1_head::RequestHead)
    requires head.method@ == crate::http1_exchange::post(), head.fields@.len() == 0,
    ensures driver::supported_request(head),
{
    assert(head.fields@ =~= Seq::<crate::headers::Field>::empty());
    reveal(Seq::filter);
}

/// Every valid path of at most 1024 bytes has a supported outgoing empty head.
/// This checks the request-side premise independently of the production branch.
pub proof fn empty_upstream_is_supported(path: Seq<u8>)
    requires crate::http1_write::target_ok(path), path.len() <= 1024,
    ensures crate::http1_exchange::request_supported(path, Seq::<crate::headers::Field>::empty()),
{
    use crate::http1_exchange as http;
    use crate::http1_write as wire;
    assert forall|all: Seq<crate::headers::Field>| http::upstream_fields(all, Seq::empty()) implies
        wire::fields_wire_ok(all) && all.len() <= crate::headers::MAX_FIELDS
            && wire::request_head_bytes(http::post(), path, all).len() <= crate::headers::MAX_BYTES by {
        assert(all.len() == 2);
        assert forall|i: int| 0 <= i < all.len() implies wire::field_wire_ok(#[trigger] all[i]) by {
            if i == 0 { assert(http::is_chunked(all[i])); } else { assert(http::is_close(all[i])); }
            framing_field_is_writable(all[i]);
        }
        reveal_with_fuel(wire::field_lines_bytes, 3);
    }
}

}
