"""Verify the actual library, then require each deliberate defect to fail its proof.

VERUS=/path/to/verus python3 scripts/check_mutations.py
Normal executable scenarios are tested separately with cargo test --workspace.

Mutations confined to the bodies of distinct exec or proof functions are checked
many to a verifier run (see "Verus's simplified VIR" below for why that is
sound); every other mutation, and any batch the VIR check cannot vouch for,
is verified on its own.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/gateway-core/src"
VERUS = os.environ.get("VERUS", "verus")
GUARD = """if !self.pending || t.owner != self.owner || t.generation != self.generation
            || count > self.offered - self.sent"""
MUTATIONS = [
    ('body_driver.rs', 'body_binding_skips_expected_key', 'if !key.same(expected)', 'if false && !key.same(expected)'),
    ('request_context.rs', 'body_binding_ignores_request', 'self.request != other.request || self.route.tenant', 'false || self.route.tenant'),
    ('request_context.rs', 'body_binding_ignores_token', '|| !equal(self.digest.as_slice(), other.digest.as_slice())', '|| false'),
    ('request_context.rs', 'body_binding_ignores_destination', '(Some(a), Some(b)) => equal(a.as_slice(), b.as_slice()),', '(Some(a), Some(b)) => true,'),
    ('exchange_driver.rs', 'body_binding_accepts_foreign_upload', '!copy.matches(&key, 0)', 'false'),
    ('exchange_driver.rs', 'body_binding_accepts_swapped_download', '!copy.matches(&key, 1)', 'false'),
    ('exchange_driver.rs', 'body_binding_discards_upload_evidence', 'Step::Uploaded(stream.out(), copy_summary(uploaded))', 'Step::Uploaded(stream.out(), None)'),
    ('body_driver.rs', 'body_binding_writes_wrong_direction', 'effects.write(context, &delivery, direction)', 'effects.write(context, &delivery, 0)'),

    ('body_driver.rs', 'body_driver_invents_eof', 'effects.read(copy.read_buffer(owner))', 'Some(0usize)'),
    ('body_driver.rs', 'body_driver_skips_audit', 'effects.audit(header, bytes)', 'None::<AuditReceipt>'),
    ('body_driver.rs', 'body_driver_skips_write', 'effects.write(context, &delivery, direction)', 'Some(delivery.bytes().len())'),
    ('body_driver.rs', 'body_driver_skips_flush', 'effects.flush()', 'true'),
    ('body_driver.rs', 'body_driver_corrupts_accepted_count', 'copy.finish_write(owner, &write, count);', 'copy.finish_write(owner, &write, Some(1));'),
    ('body_driver.rs', 'body_driver_accepts_foreign_owner', 'if owner.owner_id() != authority.request_id()', 'if false && owner.owner_id() != authority.request_id()'),
    ('request_context.rs', 'body_driver_mislabels_request', 'TransferKey { request: self.authority.request_id(), route:', 'TransferKey { request: 0, route:'),
    ('body_driver.rs', 'body_driver_mislabels_direction', 'BodyCopy::begin(owner, direction)', 'BodyCopy::begin(owner, 0)'),
    ('body_copy.rs', 'body_driver_releases_empty_slice', 'Some(Delivery { write, bytes, owner:', 'Some(Delivery { write, bytes: &[], owner:'),

    ('exchange_driver.rs', 'context_driver_admits_another_input', 'effects.admit(&head)', 'effects.admit(&RequestHead { method: Vec::new(), target: Vec::new(), fields: Vec::new() })'),
    ('exchange_driver.rs', 'context_driver_forgets_observed_input', 'Step::ReadHead(input) => input, _ => received_input(events.drop_last()),', 'Step::ReadHead(input) => None, _ => received_input(events.drop_last()),'),

    ('request_context.rs', 'context_progress_rejects_identity', '} true }, None => false,', '} false }, None => false,'),
    ('request_context.rs', 'context_progress_rejects_authorization', 'let identity = match self.policy.authenticate(digest)', 'if true { return None; }\n        let identity = match self.policy.authenticate(digest)'),
    ('policy.rs', 'context_progress_rejects_granted_route', 'if request == 0 { return None; }', 'if true { return None; }'),
    ('request_context.rs', 'context_progress_rejects_preparation', 'if self.authority.route().selector != checked.selector', 'if true { return Err(Refusal::Unavailable); }\n        if self.authority.route().selector != checked.selector'),
    ('request_context.rs', 'context_progress_rejects_supported_head', 'if head.method.len() != 4', 'if true { return Err(Refusal::Malformed); }\n        if head.method.len() != 4'),
    ('headers.rs', 'context_progress_rejects_supported_headers', 'let hop = match nominations(fields, true)', 'if true { return Err(Rejection::BadRequest); }\n    let hop = match nominations(fields, true)'),
    ('headers.rs', 'context_progress_rejects_header_projection', 'let hop = match check_request(fields)', 'if true { return Err(Rejection::BadRequest); }\n    let hop = match check_request(fields)'),
    ('request_context.rs', 'context_progress_empty_input_family', 'pub open spec fn supported_input(head: RequestHead) -> bool {\n    head.method@', 'pub open spec fn supported_input(head: RequestHead) -> bool {\n    false && head.method@'),

    ('exchange_driver.rs', 'context_driver_prepares_another_input', 'effects.upstream_head(input)', 'effects.upstream_head(&RequestHead { method: Vec::new(), target: Vec::new(), fields: Vec::new() })'),
    ('exchange_driver.rs', 'context_driver_drops_authorization_check', '&& evidence.binds(path, fields) && p.incoming == Some(evidence.input)', '&& p.incoming == Some(evidence.input)'),
    ('exchange_driver.rs', 'context_driver_unbinds_inbound_head', '&& p.incoming == Some(evidence.input) { Some(Progress', '{ Some(Progress'),
    ('exchange_driver.rs', 'context_driver_forwards_without_provider_write', '!p.forwarded && p.upstream_head_written && record_allows_forward(p, status)', '!p.forwarded && record_allows_forward(p, status)'),

    ('request_context.rs', 'context_wrong_grant_selector', 'selector: r.selector, origin: r.origin', 'selector: 0, origin: r.origin'),
    ('request_context.rs', 'context_skip_selector_binding', 'self.authority.route().selector != checked.selector || ', 'false || '),
    ('request_context.rs', 'context_skip_token_binding', '!equal(self.digest.as_slice(), checked.digest.as_slice())', 'false'),
    ('request_context.rs', 'context_skip_endpoint_binding', 'if !crate::inbound::matches_endpoint', 'if false && !crate::inbound::matches_endpoint'),
    ('request_context.rs', 'context_replace_provider_path', 'slice_to_vec(p.destination.path.as_slice())', 'slice_to_vec(b"/wrong")'),
    ('request_context.rs', 'context_replace_provider_credential', 'p.credential.value.as_slice())', 'b"wrong-secret")'),
    ('request_context.rs', 'context_change_selected_destination', 'destination, credential, egress })', 'destination: &self.destinations[0], credential, egress })'),
    ('request_context.rs', 'context_change_selected_credential', 'destination, credential, egress })', 'destination, credential: &self.credentials[0], egress })'),
    ('request_context.rs', 'context_invent_body_failure', 'copy.write_bytes(stream, &self.authority, journal, route)', 'None'),

    ('exchange_driver.rs', 'end_to_end_discards_valid_request', '    let body_framing = match framing(&head.fields, true) {', '    if true { return d.close_without(effects); }\n    let body_framing = match framing(&head.fields, true) {'),
    ('exchange_driver.rs', 'end_to_end_always_fails_exchange', '    match d.exchange(effects, &mut life, strict, &head) {', '    match Err::<(), Fault>(Fault::Metadata) {'),
    ('exchange_driver.rs', 'end_to_end_reports_failure_after_success', '        life.succeeded(copy.body_copy());', '        life.failed(Fault::Download);'),
    ('exchange_driver.rs', 'end_to_end_corrupts_completion', 'let recorded = effects.audit_completion(&payload);', 'let recorded = effects.audit_completion(&Vec::new());'),
    ('exchange_driver.rs', 'end_to_end_skips_response_after_upload', '        // Response heads until a final one; the machine classifies each.', '        if true { return Err(Fault::Http); }\n        // Response heads until a final one; the machine classifies each.'),
    ('http1_exchange.rs', 'end_to_end_request_writer_rejects_everything', '        if self.sent_head { return None; }', '        if true { return None; }'),
    ('http1_exchange.rs', 'end_to_end_response_writer_rejects_everything', '        if self.phase != Phase::Open || status < 200 || status > 599 || status == 204 || status == 304 { return None; }', '        if true { return None; }'),
    ('headers.rs', 'end_to_end_response_projection_rejects_everything', '    let hop = match nominations(fields, false) {', '    if true { return Err(Rejection::BadRequest); }\n    let hop = match nominations(fields, false) {'),
    ('exchange_driver.rs', 'end_to_end_success_premise_is_empty', '    200 <= head.status <= 599 && !crate::http1_framing::framing_spec_refused(head.fields@)', '    false && 200 <= head.status <= 599 && !crate::http1_framing::framing_spec_refused(head.fields@)'),
    ('projection.rs', 'projection_json_erases_response_text', 'ParsedResponse { text, choices_known: false, usage: usage_of(value), model, failed: semantics::failed(value) }', 'ParsedResponse { text: Vec::new(), choices_known: false, usage: usage_of(value), model, failed: semantics::failed(value) }'),
    ('projection.rs', 'projection_json_drops_text_block', 'if is_text {', 'if false && is_text {'),
    ('projection.rs', 'projection_json_drops_item_text', 'if let Some(t) = text_of_content(c) {', 'if let Some(t) = None::<Vec<u8>> {'),
    ('projection.rs', 'projection_json_overrides_raw_fallback', 'if unparsed { truncated_text(exchange.download.as_slice(), max_text) }', 'if unparsed { truncated_text(b"", max_text) }'),
    ('shipping_driver.rs', 'projection_enqueue_discards_body', 'machine.enqueue(token, projected.body, projected.rows)', 'machine.enqueue(token, Vec::new(), projected.rows)'),
    ('shipping_driver.rs', 'projection_serializes_wrong_row', 'crate::json::write(&rows[1])', 'crate::json::write(&rows[0])'),
    ('shipping_driver.rs', 'projection_body_omits_assistant', 'crate::framing::append(&mut body, second.as_slice());', '// dropped assistant document'),
    ('shipping_driver.rs', 'projection_miscounts_rows', 'Projected { body, rows: 2 }', 'Projected { body, rows: 1 }'),
    ('exchange_driver.rs', 'coverage_start_append_omitted', 'let started = effects.audit_request_start();', 'let started = true;'),
    ('exchange_driver.rs', 'coverage_response_append_omitted', 'let logged = effects.audit_response_head(status);', 'let logged = true;'),
    ('exchange_driver.rs', 'coverage_completion_append_omitted', 'let recorded = effects.audit_completion(&payload);', 'let recorded = true;'),
    ('exchange_driver.rs', 'coverage_duplicate_client_write', 'let ok = effects.write_client(&bytes, scope);', 'let _extra = effects.write_client(&bytes, scope);\n        let ok = effects.write_client(&bytes, scope);'),
    ('exchange_driver.rs', 'coverage_wrong_provider_path', 'upstream.request(path.as_slice(), fields)', 'upstream.request(b"/wrong-endpoint", fields)'),
    ('exchange_driver.rs', 'coverage_provider_status_replaced', 'UpstreamStatus::Framed(framing) => return Ok((status_head.status, status_head.fields, framing)),', 'UpstreamStatus::Framed(framing) => return Ok((200, status_head.fields, framing)),'),
    ('serve_driver.rs', 'coverage_worker_close_omitted', '    effects.close_workers();', '    // omitted worker closure'),
    ('config_build.rs', 'coverage_wrong_secret_name', 'secrets.get(entry.env.as_slice())', 'secrets.get(b"UNRELATED_SECRET")'),
    ('headers.rs', 'coverage_drop_allowed_headers', 'if allowed_name(request, field.name.as_slice()) && !listed(hop, field.name.as_slice()) {', 'if false && allowed_name(request, field.name.as_slice()) && !listed(hop, field.name.as_slice()) {'),
    ('policy.rs', 'coverage_policy_always_rejects', '        let mut i: usize = 0;\n        while i < identities.len()', '        if true { return None; }\n        let mut i: usize = 0;\n        while i < identities.len()'),
    ("deadline.rs", "scope_budget_renews_descendant", "Self { root: self.root, end }", "Self { root: self.root, end: self.root }"),
    ("deadline.rs", "scope_budget_uses_ancestor_for_io", "{ run(io, self.end) }", "{ run(io, self.root) }"),
    ("scope.rs", "scope_budget_skips_cleanup", "    effects.cleanup();", "    // cleanup omitted"),
    ("scope.rs", "scope_budget_cleans_twice", "    effects.cleanup();", "    effects.cleanup(); effects.cleanup();"),
    ("exchange_driver.rs", "scope_budget_forwards_with_control_deadline",
        "if !self.emit(effects, head, WriteScope::Exchange)", "if !self.emit(effects, head, WriteScope::Control)"),
    ("cancellation.rs", "cancellation_eof_closes_receive_side",
        "Observation::EndOfInput => !world.peer_sends,",
        "Observation::EndOfInput => !world.peer_sends && !world.peer_receives,"),
    ("cancellation.rs", "cancellation_eof_or_read_fault_cancels",
        "Observation::EndOfInput | Observation::ReadFault => Decision::StopWatching,",
        "Observation::EndOfInput | Observation::ReadFault => Decision::Cancel(Permit { observation }),"),
    ("cancellation.rs", "cancellation_retries_cancel",
        "Observation::Data | Observation::RetryRead => Decision::Continue,",
        "Observation::Data | Observation::RetryRead => Decision::Cancel(Permit { observation }),"),
    ("cancellation.rs", "cancellation_ignores_valid_evidence",
        "Decision::Cancel(Permit { observation }),", "Decision::StopWatching,"),
    ("cancellation.rs", "cancellation_forges_evidence",
        "Decision::Cancel(Permit { observation }),",
        "Decision::Cancel(Permit { observation: Observation::EndOfInput }),"),
    ('http1_framing.rs', 'http_length_rejects_zero_padding', '    if value.len() == 0 { return None; }\n    let mut acc: u64 = 0;', '    if value.len() == 0 || (value.len() > 1 && value[0] == 48) { return None; }\n    let mut acc: u64 = 0;'),
    ('http1_framing.rs', 'http_length_dispatches_canonical_parser', 'match parse_content_length(fields[i].value.as_slice())', 'match parse_decimal(fields[i].value.as_slice())'),
    ('http1_framing.rs', 'http_length_discards_result', 'Some(acc)\n}\n\n/// The `u64`', 'Some(0)\n}\n\n/// The `u64`'),
    ('http1_exchange.rs', 'http_bodiless_invents_length', 'if status != 204 && status != 304 { all.push(length_field(body.len())); }', 'all.push(length_field(body.len()));'),
    ('http1_exchange.rs', 'http_bodiless_allows_supplied_length', 'if body.len() > 0 || crate::headers::has(&fields, CONTENT_LENGTH.as_slice())', 'if body.len() > 0'),
    ('http1_exchange.rs', 'http_bodiless_allows_supplied_coding', '|| crate::headers::has(&fields, TRANSFER_ENCODING.as_slice()) { return None; }', '{ return None; }'),

    ('projection.rs', 'projection_response_prefix_gate', 'None => (parse_sse(bytes), is_sse(bytes)),', 'None => {\n            if bytes.len() < 5 || !bytes_eq(slice_subrange(bytes, 0, 5), b"data:") {\n                return (ParsedResponse { text: Vec::new(), choices_known: false, usage: None, model: None, failed: false }, false);\n            }\n            (parse_sse(bytes), is_sse(bytes))\n        },'),
    ('projection.rs', 'projection_response_skips_event', 'Some(Some(value)) => sse_event(&value, &mut out, &mut usage, &mut saw_usage),', 'Some(Some(_value)) => {},'),
    ('projection.rs', 'projection_response_erases_failure', 'out.failed = out.failed || semantics::failed(event);', 'out.failed = semantics::failed(event);'),
    ('projection.rs', 'projection_response_json_ignores_failure', 'model, failed: semantics::failed(value)', 'model, failed: false'),
    ('projection.rs', 'projection_response_rows_ignore_failure', 'let is_error = response.failed || (match status', 'let is_error = (match status'),
    ('projection.rs', 'projection_response_serializes_success', 'push_member(&mut ms, K_IS_ERROR.as_slice(), boolean(shared.is_error));', 'push_member(&mut ms, K_IS_ERROR.as_slice(), boolean(false));'),
    ('response_semantics.rs', 'projection_response_ignores_nested_failure', 'local(v) || match get(v, RESPONSE.as_slice()) { Some(w) => local(w), None => false }', 'local(v)'),
    ('response_semantics.rs', 'projection_response_ignores_error_type', '|| is_named(kind, ERROR.as_slice()) || is_named(kind, RESPONSE_FAILED.as_slice())', '|| is_named(kind, ERROR.as_slice())'),
    ('response_semantics.rs', 'projection_response_null_is_error', 'Some(w) => !matches!(w, Value::Null), None => false', 'Some(_w) => true, None => false'),
    ('sse.rs', 'projection_response_keeps_bom', 'let start = if bytes.len() >= 3 && bytes[0] == 239 && bytes[1] == 187 && bytes[2] == 191 { 3 } else { 0 };', 'let start = 0;'),

    ("sse.rs", "projection_sse_drops_valid_json", 'Some(crate::json::parse(data.as_slice()))', 'Some(None)'),
    ("projection.rs", "projection_null_usage_as_zero", '    if !matches!(usage, Value::Object(_)) { return None; }', ''),
    ("projection.rs", "projection_unknown_usage_erases_known", 'if let Some(u) = usage_of(event) { *usage = u; *saw_usage = true; }', 'if let Some(u) = usage_of(event) { *usage = u; *saw_usage = true; } else { usage.input = 0; }'),
    ('projection.rs', 'projection_usage_start_discards_output', 'if let Some(u) = usage_of(message) {\n                *usage = u; *saw_usage = true;', 'if let Some(u) = usage_of(message) {\n                *usage = u; usage.output = 0; *saw_usage = true;'),
    ('projection.rs', 'projection_usage_delta_erases_input', 'usage.output = n; *saw_usage = true;', 'usage.output = n; usage.input = 0; *saw_usage = true;'),
    ('projection.rs', 'projection_usage_ignores_explicit_zero', 'usage.output = n; *saw_usage = true;', 'if n != 0 { usage.output = n; } *saw_usage = true;'),
    ('projection.rs', 'projection_usage_wrong_cache_normalization', 'let input = if anthropic { total_input } else if total_input >= cache_read { total_input - cache_read } else { 0 };', 'let input = total_input;'),
    ('projection.rs', 'projection_usage_serializes_zero', 'push_member(&mut ms, K_OUTPUT_TOKENS.as_slice(), number(usage.output));', 'push_member(&mut ms, K_OUTPUT_TOKENS.as_slice(), number(0));'),
    ('projection.rs', 'projection_usage_discards_fold', 'out.usage = if saw_usage { Some(usage) } else { None };', 'out.usage = None;'),
    ('projection.rs', 'projection_choices_discards_result', 'if known { out.text = text; }', 'if known { out.text = Vec::new(); }'),
    ('projection.rs', 'projection_choices_bypasses_dispatch', 'let (text, known) = choices::parse(bytes);', 'let (text, known) = (Vec::new(), false);'),
    ('projection.rs', 'projection_choices_serializes_other_text', 'else { capped(response.text.as_slice(), max_text) };', 'else { capped(b"", max_text) };'),
    ('response_choices.rs', 'projection_choices_loses_index', 'out.push(Piece { index: id, text: t });', 'out.push(Piece { index: 0, text: t });'),
    ('response_choices.rs', 'projection_choices_skips_event', 'Some(Some(v)) => extend(&v, &mut p),', 'Some(Some(_v)) => {},'),
    ('response_choices.rs', 'projection_choices_skips_item', 'add(&choices[i], out);', '// dropped fragment'),
    ('response_choices.rs', 'projection_choices_cross_contamination', 'if p[i].index == id { append_line(&mut out, false, p[i].text.as_slice()); }', 'append_line(&mut out, false, p[i].text.as_slice());'),
    ('response_choices.rs', 'projection_choices_duplicates_alternative', 'if !was_seen(p, i) {', 'if true {'),
    ('response_choices.rs', 'projection_choices_omits_separator', 'append_line(&mut out, i > 0, text.as_slice());', 'append_line(&mut out, false, text.as_slice());'),
    ("sse.rs", "projection_sse_omits_data_separator", 'if present { data.push(10); }', 'if present { data.push(32); }'),
    ("sse.rs", "projection_sse_drops_data", 'crate::framing::append(&mut data, more);', '// Omitted data must violate the event grammar.'),
    ("sse.rs", "projection_sse_dispatches_at_eof", 'if end == self.bytes.len() { self.start = end; return None; }', 'if end == self.bytes.len() { self.start = end; return Some(data); }'),
    ("sse.rs", "projection_sse_dispatches_nonblank_line", 'if line.len() == 0 {\n                self.start = next;', 'if line.len() != 0 {\n                self.start = next;'),
    ("sse.rs", "projection_sse_keeps_optional_space", 'let start = if line.len() > 5 && line[5] == 32 { 6 } else { 5 };', 'let start = 5;'),
    ("sse.rs", "projection_sse_splits_crlf", 'let next = if end == bytes.len() { end }\n        else if bytes[end] == 13 && end + 1 < bytes.len() && bytes[end + 1] == 10 { end + 2 }', 'let next = if end == bytes.len() { end }\n        else if bytes[end] == 13 && end + 1 < bytes.len() && bytes[end + 1] == 10 { end + 1 }'),
    ("shipping_progress.rs", "progress_drain_skips_round", "successful_round(m, w.now, w.upload_at, w.expires_at, w.status);", "// Missing round must violate the decreasing rank."),
    ("enrollment.rs", "progress_fresh_token_refresh_loop", "(!self.fresh && expires_at - now <= RENEWAL_WINDOW_SECONDS)", "(expires_at - now <= RENEWAL_WINDOW_SECONDS)"),
    ("enrollment.rs", "progress_enrollment_never_fresh", "self.fresh = true;", "self.fresh = false;"),
    ("enrollment.rs", "progress_fresh_token_never_expires", "expires_at <= now || (!self.fresh", "false || (!self.fresh"),
    ("shipping_progress.rs", "progress_witness_omits_ack", "m.reply(upload_at, Reply { status, retry_after: None, revocation: false, credential: None });", "// Missing acknowledgment must not count as progress."),

    ("config_schema.rs", "buffered_default_weakens_durability", "None => Durability::Durable,", "None => Durability::Buffered,"),
    ("journal_binding.rs", "buffered_receipt_under_durable_policy", "!self.require_sync || durable", "true"),
    ("audit_receipt.rs", "buffered_receipt_claims_durable", "durable: self.sync_required()", "durable: true"),
    ('batch_worker.rs', 'batch_skips_sync', 'accepted = !journal.sync_required() || storage.sync();', 'accepted = true;'),
    ('batch_worker.rs', 'batch_skips_write', 'if write_frames(&batch.jobs, 0, storage)', 'if true'),
    ('batch_worker.rs', 'batch_ignores_write_failure', 'if !storage.write_all(jobs[at].0.bytes()) { return false; }', 'let _ = storage.write_all(jobs[at].0.bytes());'),
    ('batch_worker.rs', 'batch_ignores_sync_failure', 'if !accepted { journal.fail(); }', 'if false { journal.fail(); }'),
    ('batch_worker.rs', 'batch_foreign_journal', 'enabled && journal.session_id() == batch.session && !journal.is_failed()', 'enabled && !journal.is_failed()'),
    ('batch_worker.rs', 'batch_disabled_io', 'enabled && journal.session_id() == batch.session && !journal.is_failed()', 'journal.session_id() == batch.session && !journal.is_failed()'),
    ('batch_worker.rs', 'batch_dequeues_while_busy', '!self.busy && self.next < u64::MAX', 'self.next < u64::MAX'),
    ('batch_worker.rs', 'batch_wrong_release_session', ' || token.session != self.session', ''),
    ('batch_worker.rs', 'batch_wrong_release_generation', ' || token.generation != self.next - 1', ''),
    ('batch_worker.rs', 'batch_lifo_receipts', 'let (frame, completion) = jobs.remove(0);', 'let (frame, completion) = jobs.pop().unwrap();'),
    ('batch_worker.rs', 'batch_ignores_payload_limit', ' || queue.payload_capacity() > self.limit', ''),
    ('batch_worker.rs', 'batch_omits_active_budget', '<= (queue.capacity() + MAX_BATCH) * (self.limit() + 65),', '<= queue.capacity() * (self.limit() + 65),'),

    ("s3_delivery.rs", "s3_date_uses_month_as_day", "push_two(&mut out, c.day as u64)", "push_two(&mut out, c.month as u64)"),
    ("s3_delivery.rs", "s3_omits_signed_date_header", 'headers.push(field(b"x-amz-date", date, false));', 'headers.push(field(b"wrong-header", date, false));'),
    ("s3_delivery.rs", "s3_fabricates_success_without_put", "let response = io.put(put);", "let response = Response { status: 200, retry_after: None };"),
    ("s3_config.rs", "hypaware_ignores_configured_path", '        if parts.path.len() != 1 || parts.path[0] != 47 { return Err(Error::Destination); }', ""),
    ("s3_config.rs", "s3_reads_wrong_secret_name", "secrets.read(s.token_env.as_slice())", "secrets.read(s.s3_access_key_env.as_slice())"),
    ("shipping_checkpoint.rs", "s3_checkpoint_omits_prefix", "append(&mut raw, c.prefix.as_slice());", ""),
    ("shipping_checkpoint.rs", "s3_checkpoint_ignores_limits", "if crate::headers::eq(c.session.as_slice(), identity) && c.max_open_exchanges == open && c.max_exchange_bytes == bytes", "if crate::headers::eq(c.session.as_slice(), identity)"),
    ("shipping_checkpoint.rs", "s3_checkpoint_fabricates_progress", "session: vstd::slice::slice_to_vec(identity), resolved, poisoned,", "session: vstd::slice::slice_to_vec(identity), resolved: 0, poisoned,"),
    ("s3_driver.rs", "s3_driver_bypasses_delivery", "s3_delivery::send(self.config, self.io, request, ms)", "crate::s3::activation()"),
    ("s3.rs", "s3_accepts_failed_put", "if status == 200 { 200 }", "if status == 403 { 200 }"),
    ("s3.rs", "s3_changes_hmac_pad", "padded(k.as_slice(), 0x36)", "padded(k.as_slice(), 0x5c)"),
    ("s3.rs", "s3_signs_wrong_service", 'mac(k_region.as_slice(), b"s3")', 'mac(k_region.as_slice(), b"ec2")'),
    ("s3.rs", "s3_omits_payload_binding", 'let payload_hash = hex(sha256::digest(body).as_slice());', 'let payload_hash = hex(sha256::digest(b"wrong").as_slice());'),
    ("s3.rs", "s3_allows_query_in_prefix", "b == 95 || (slash && b == 47)", "b == 95 || b == 63 || (slash && b == 47)"),
    ("log_rotation.rs", "rotation_skips_seal", "let sealed = self.io.seal();", "let sealed = true;"),
    ("log_rotation.rs", "rotation_ignores_seal_failure", "if !sealed { self.failed = true; return false; }", "if false { self.failed = true; return false; }"),
    ("snapshot.rs", "snapshot_reads_past_capture", "let max = if remaining < needed as u64 { remaining as usize } else { needed };", "let max = needed;"),
    ("snapshot.rs", "snapshot_skips_cursor_bytes", "self.position += (bytes.len() - before) as u64;", "self.position += max as u64;"),
    ("snapshot.rs", "snapshot_hides_incomplete_tail", "ReadError::Eof } else { ReadError::Incomplete", "ReadError::Eof } else { ReadError::Eof"),
    ("snapshot.rs", "snapshot_hides_read_failure", "self.errors@ = self.errors@ + 1; }\n                return Err(ReadError::Io);", "self.errors@ = self.errors@ + 1; }\n                return Err(ReadError::Eof);"),
    ("snapshot.rs", "snapshot_retries_uncertain_cursor", "if self.failed { proof { self.errors@ = self.errors@ + 1; } return Err(ReadError::Io); }", ""),
    ("snapshot.rs", "snapshot_seeks_outside_capture", "if offset > self.length { return false; }", "if false { return false; }"),
    ("snapshot.rs", "snapshot_ignores_seek_failure", "if !self.file.seek(offset) { return false; }", "if false { return false; }"),
    ("snapshot.rs", "snapshot_forgets_seek_cursor", "self.position = offset;", "self.position = self.position;"),

    ("session_recovery.rs", "session_recovery_skips_sealed_recheck",
        "// closes the race between an earlier snapshot EOF and rotation.\n            match self.read_current()",
        "// closes the race between an earlier snapshot EOF and rotation.\n            match Ok::<Option<RecoveredRecord>, ScanError>(None)"),
    ("session_recovery.rs", "session_recovery_accepts_foreign_successor",
        "if candidate.session() != self.session", "if false"),
    ("session_recovery.rs", "session_recovery_accepts_replaced_current",
        "if scanner.session() != self.session", "if false"),
    ("session_recovery.rs", "session_recovery_restarts_at_header",
        "scanner.restart(self.offset)", "scanner.restart(56)"),
    ("session_recovery.rs", "session_recovery_repeats_cursor",
        "self.offset = scanner.offset();", "self.offset = self.offset;"),
    ("session_recovery.rs", "session_recovery_skips_first_record_in_successor",
        "self.index = next;\n            self.offset = 56;", "self.index = next;\n            self.offset = 124;"),
    ("session_recovery.rs", "session_recovery_returns_false_eof",
        "let out = scanner.next_record();", "let out: Result<Option<RecoveredRecord>, ScanError> = Ok(None);"),
    ("session_recovery.rs", "session_recovery_retries_terminal_errors",
        "if self.failed { return Ok(None); }", "if false { return Ok(None); }"),

    ("log_rotation.rs", "rotation_ignores_age", "length > limit - used || expired", "length > limit - used"),
    ("log_rotation.rs", "rotation_splits_empty_segment", "used > 56 && (used > limit", "used >= 56 && (used > limit"),
    ("log_rotation.rs", "rotation_skips_append", "let appended = self.io.append(bytes);", "let appended = true;"),
    ("log_rotation.rs", "rotation_skips_sync", "let ok = self.io.sync();", "let ok = true;"),
    ("log_rotation.rs", "rotation_reuses_index", "let next = self.index + 1;", "let next = self.index;"),
    ("log_rotation.rs", "rotation_ignores_create_failure", "if !created { self.failed = true; return false; }", "if false { self.failed = true; return false; }"),

    ("deadline.rs", "deadline_renews_budget", "Some(end - now)", "Some(end)"),
    ("deadline.rs", "deadline_accepts_late_completion", "if finish < end { Some(result) } else { None }", "Some(result)"),
    ("deadline.rs", "deadline_skips_io", "let result = io.perform(budget);", "return None; let result = io.perform(budget);"),
    ("deadline.rs", "deadline_performs_twice", "let result = io.perform(budget);", "let result = io.perform(budget); let result = io.perform(budget);"),
    ("inbound.rs", "sdk_target_rejects_valid_route", "            Some((n, end))", "            None"),
    ("inbound.rs", "sdk_target_changes_route", "            Some((n, end))", "            Some((0, end))"),
    ("inbound.rs", "sdk_target_changes_boundary", "            Some((n, end))", "            Some((n, 0))"),
    ("inbound.rs", "sdk_endpoint_accepts_mismatch", "end == path.len() || eq(slice_subrange(path, end, path.len()), endpoint)", "true"),
    ("task_credit.rs", "task_result_accepts_foreign_source", "if self.source != credit.owner_id() { return Err(self); }", ""),
    ("task_credit.rs", "task_result_skips_destination_handoff", "if !credit.handoff_to(registry, owner) { return Err(self); }", ""),
    ("task_credit.rs", "task_result_issues_wrong_source", "TaskResult { source: self.key.owner(), value }", "TaskResult { source: 0, value }"),
    ("task_credit.rs", "task_result_issues_without_completed_work", "if !self.finish_work() { return Err(value); }", ""),
    ("task_credit.rs", "task_result_denies_valid_handoff", "Ok(self.value)", "Err(self)"),
    ("http_worker.rs", "worker_http_duplicate_role", " || self.slots[issuer.index].issued[role]", ""),
    ("http_worker.rs", "worker_http_late_issuance", "self.slots[issuer.index].retired || ", ""),
    ("http_worker.rs", "worker_http_foreign_issuer", " || self.slots[issuer.index].owner != issuer.owner", ""),
    ("http_worker.rs", "worker_http_wrong_role", "HttpPermit { index: issuer.index, owner: issuer.owner, role }", "HttpPermit { index: issuer.index, owner: issuer.owner, role: 0 }"),
    ("http_worker.rs", "worker_http_loses_charge", "self.slots[issuer.index].active[role] = true;", "self.slots[issuer.index].active[role] = false;"),
    ("http_worker.rs", "worker_http_foreign_cleanup", " || self.slots[permit.index].owner != permit.owner", ""),
    ("http_worker.rs", "worker_http_clears_wrong_role", "self.slots[permit.index].active[permit.role] = false;", "self.slots[permit.index].active[0] = false;"),
    ("http_worker.rs", "worker_http_releases_live_resource", " || self.slots[index].is_active()", ""),
    ("http_worker.rs", "worker_http_release_allows_late_issue", "self.slots[index].retired = true;", "self.slots[index].retired = false;"),
    ("http_worker.rs", "worker_http_failure_keeps_admission_open", "if !ok { self.admission.close(); }", ""),
    ("http_worker.rs", "worker_http_omits_active_roles", "if self.slots[i].active[role] { count = count + 1; }", "if false { count = count + 1; }"),
    ("http_accounting.rs", "http_accounting_omits_sender_tails", " + crate::http_worker::role_count(workers.slots(), RESPONSE_WRITER as int)", ""),
    ("http_accounting.rs", "http_accounting_omits_output_readers", " + crate::http_worker::role_count(workers.slots(), OUTPUT_READER as int)", ""),
    ("http_connection.rs", "response_registry_reissues_after_cleanup", "let ok = self.responses[response.index].finish(response.permit);", "let ok = self.responses[response.index].finish(response.permit); self.responses[response.index].issued = false;"),
    ("http_connection.rs", "response_registry_overwrites_live_slot", "self.responses.set(index, slot);", "self.responses.set(0, slot);"),
    ("http_connection.rs", "response_registry_accepts_stale_issuer", " || self.responses[issuer.index].owner != issuer.owner", ""),
    ("http_connection.rs", "response_registry_binds_wrong_slot", "RegisteredResponse { index: issuer.index, permit }", "RegisteredResponse { index: 0, permit }"),
    ("http_connection.rs", "response_registry_issues_wrong_owner", "ResponseIssuer { index, owner }", "ResponseIssuer { index, owner: 0 }"),
    ("http_connection.rs", "response_registry_loses_active_charge", "if self.responses[i].active { count = count + 1; }", "if false { count = count + 1; }"),
    ("http_connection.rs", "response_registry_denies_valid_release", "self.responses[index].release_task(task, &mut self.admission)", "self.responses[index].release_task(task, &mut self.admission); false"),
    ("http_connection.rs", "response_registry_hides_active_permits", "count_where(slots, |s: ResponseSlot| s.active())", "count_where(slots, |s: ResponseSlot| false)"),
    ("http_connection.rs", "response_duplicate_issuance", "if self.issued || self.retired", "if self.retired"),
    ("http_connection.rs", "response_late_issuance", "if self.issued || self.retired", "if self.issued"),
    ("http_connection.rs", "response_wrong_permit_owner", "ResponsePermit { owner: self.owner }", "ResponsePermit { owner: 0 }"),
    ("http_connection.rs", "response_foreign_cleanup", "if !self.active || permit.owner != self.owner", "if !self.active"),
    ("http_connection.rs", "response_release_with_live_body", "if self.active || self.owner != task.owner_id()", "if self.owner != task.owner_id()"),
    ("http_connection.rs", "response_release_foreign_task", "if self.active || self.owner != task.owner_id()", "if self.active"),
    ("http_connection.rs", "response_release_allows_late_issue", "self.retired = true;", "self.retired = false;"),
    ("task_credit.rs", "task_cleanup_accepts_unfinished_owner", "if !cleanup.cleanup.is_finished() || cleanup.owner != self.key.owner()", "if cleanup.owner != self.key.owner()"),
    ("task_credit.rs", "task_cleanup_accepts_foreign_owner", "if !cleanup.cleanup.is_finished() || cleanup.owner != self.key.owner()", "if !cleanup.cleanup.is_finished()"),
    ("task_credit.rs", "task_cleanup_issues_wrong_identity", "TaskCleanup { owner: self.key.owner(),", "TaskCleanup { owner: 0,"),
    ("task_credit.rs", "task_cleanup_issues_without_transition", "if !self.begin_cleanup() { return Err(value); }", "if false { return Err(value); }"),

    ("http_message.rs", "http_message_omits_data_bytes", "Self::Data(frame) => frame.contents()", "Self::Data(frame) => Seq::empty()"),

    ("http_message.rs", "http_message_cleanup_releases_on_extraction", "if cleanup.finished() { 0 }", "if cleanup.started() { 0 }"),
    ("http_message.rs", "http_message_counts_only_queue_after_close", "message_bytes(queue.item()) + cleanup_bytes(cleanup) <= 16384,", "message_bytes(queue.item()) + cleanup_bytes(cleanup) <= 0,"),

    ("output_frame.rs", "output_frame_ignores_hard_limit", "let cap = if requested < MAX_OUTPUT_FRAME { requested } else { MAX_OUTPUT_FRAME };", "let cap = requested;"),
    ("output_frame.rs", "output_frame_ignores_requested_limit", "let cap = if requested < MAX_OUTPUT_FRAME { requested } else { MAX_OUTPUT_FRAME };", "let cap = MAX_OUTPUT_FRAME;"),
    ("output_frame.rs", "output_frame_corrupts_payload", "slice_to_vec(slice_subrange(bytes, 0, count))", "slice_to_vec(slice_subrange(bytes, 0, 0))"),
    ("output_frame.rs", "output_frame_loses_handoff_payload", "{ self.bytes }", "{ Vec::new() }"),
    ("output_frame.rs", "output_frame_understates_length", "{ self.bytes.len() }", "{ 0 }"),

    ("resolved_route.rs", "dispatch_submits_with_unbound_route", "if !self.matches(authority) { return None; }", ""),

    ("resolved_route.rs", "resolved_route_wrong_destination", "destination: &destinations[route.origin]", "destination: &destinations[0]"),
    ("resolved_route.rs", "resolved_route_wrong_credential", "credential: &credentials[route.credential]", "credential: &credentials[0]"),
    ("resolved_route.rs", "resolved_route_ignores_request", "self.request == authority.request_id() && ", ""),
    ("resolved_route.rs", "resolved_route_ignores_credential", "&& self.route.credential == route.credential", ""),
    ("resolved_route.rs", "resolved_route_releases_unbound_target", "if self.matches(authority) { Some(self.destination) }", "if true { Some(self.destination) }"),

    ("submission.rs", "direction_ignores_receipt_at_prepare", " || stream.recorded_direction() != direction", ""),
    ("submission.rs", "direction_ignores_receipt_at_submission", " || owner.recorded_direction() != direction", ""),
    ("submission.rs", "direction_uses_opposite_ticket", " || self.direction != direction", ""),
    ("submission.rs", "direction_mints_wrong_ticket", "request: authority.request_id(), direction", "request: authority.request_id(), direction: 0"),
    ("submission.rs", "direction_accepts_invalid_direction", "if direction > 1 { return None; }", ""),

    ("submission.rs", "provenance_prepare_without_evidence", "if stream.stream().requires_audit() && (!stream.is_audited_for(authority, journal) || stream.recorded_direction() != direction) { return None; }", ""),
    ("submission.rs", "provenance_bytes_without_evidence", "if owner.stream().requires_audit() && (!owner.is_audited_for(authority, journal) || owner.recorded_direction() != direction) { return None; }", ""),
    ("owned_stream.rs", "provenance_reuses_prior_chunk", "if out.is_some() { self.clear_audit(); }", ""),
    ("owned_stream.rs", "provenance_forges_receipt_session", "self.audit_session = Some(receipt.session_id());", "self.audit_session = Some(0);"),
    ("owned_stream.rs", "provenance_omits_receipt_evidence", "self.audit = Ghost(Some(*receipt));", "self.audit = Ghost(None);"),
    ("owned_stream.rs", "provenance_ignores_designated_journal", " && journal.matches_session(self.audit_session)", ""),

    ("submission.rs", "submission_issues_for_wrong_request", "if stream.owner_id() != authority.request_id()", "if false"),
    ("submission.rs", "submission_uses_another_origin", "ticket, route, request:", "ticket, route: Route { origin: 0, ..route }, request:"),
    ("submission.rs", "submission_accepts_another_origin", " || self.route.origin != route.origin", ""),
    ("submission.rs", "submission_accepts_another_credential", " || self.route.credential != route.credential", ""),
    ("submission.rs", "submission_accepts_another_selector", " || self.route.selector != route.selector", ""),
    ("submission.rs", "submission_accepts_another_tenant", "self.route.tenant != authority.tenant_id() || ", ""),

    ("journal_binding.rs", "binding_replaces_designated_session", "Some(current) => current == session,", "Some(current) => { self.session = Some(session); true },"),
    ("journal_binding.rs", "binding_accepts_foreign_receipt", "Some(session) => session == receipt.session_id() && self.accepts_durability(receipt.is_durable()),", "Some(session) => true,"),
    ("journal_binding.rs", "binding_accepts_undesignated_receipt", "None => false,", "None => true,"),
    ("stream.rs", "binding_receipt_session_check_omitted", "if !journal.accepts(receipt) { return false; }", ""),

    ("journal.rs", "journal_session_wrong_ticket", "Some(Append { session: self.session,", "Some(Append { session: 0,"),
    ("journal.rs", "journal_session_wrong_receipt", "Some(DurableFrame { session: self.session,", "Some(DurableFrame { session: 0,"),
    ("journal.rs", "journal_session_accepts_foreign_ticket", "if self.failed || t.session != self.session || t.start != self.written", "if self.failed || t.start != self.written"),
    ("journal.rs", "journal_session_commits_foreign_ticket", "if t.session != self.session || t.start", "if t.start"),
    ("disk_worker.rs", "disk_session_accepts_foreign_journal", "if enabled && journal.session_id() == self.session {", "if enabled {"),

    ("disk_worker.rs", "disk_syncs_after_permanent_failure", "let mut receipt = None;", "let mut receipt = None; let _ = storage.sync();"),
    ("disk_worker.rs", "disk_release_accepts_another_session", " || token.session != self.session", ""),
    ("disk_worker.rs", "disk_dequeues_while_active", "if self.busy || self.next == u64::MAX", "if self.next == u64::MAX"),
    ("disk_worker.rs", "disk_forgets_active_charge", "self.busy = true;", "self.busy = false;"),
    ("disk_worker.rs", "disk_reuses_active_generation", "self.next += 1;", "self.next = self.next;"),
    ("disk_worker.rs", "disk_release_accepts_wrong_generation", " || token.generation != self.next - 1", ""),
    ("disk_worker.rs", "disk_ignores_payload_budget", " || queue.payload_capacity() > self.payload_limit", ""),
    ("disk_worker.rs", "disk_commits_without_write", "storage.write_all(self.frame.bytes()) && storage.sync()", "storage.sync()"),
    ("disk_worker.rs", "disk_commits_without_sync", "storage.write_all(self.frame.bytes()) && storage.sync()", "storage.write_all(self.frame.bytes())"),
    ("disk_worker.rs", "disk_writes_when_disabled", "if enabled && journal.session_id() == self.session {", "if journal.session_id() == self.session {"),
    ("disk_worker.rs", "disk_bound_omits_active_credit", "<= (queue.capacity() + 1) * (self.payload_limit() + 65),", "<= queue.capacity() * (self.payload_limit() + 65),"),
    ("task_credit.rs", "task_handoff_without_live_owner", " || !owner.is_live(registry)", ""),
    ("task_credit.rs", "task_handoff_wrong_owner", "Phase::HandedOff(owner.owner_id())", "Phase::HandedOff(0)"),
    ("task_credit.rs", "task_handoff_before_result", "if !matches!(self.phase, Phase::AwaitingAdoption) || !owner.is_live(registry)", "if !owner.is_live(registry)"),
    ("task_credit.rs", "task_completed_work_releases_unread_reply", "self.phase = Phase::AwaitingAdoption;", "self.phase = Phase::Cleaned;"),
    ("task_credit.rs", "task_start_keeps_credit_releasable", "self.phase = Phase::Running;", "self.phase = Phase::Reserved;"),
    ("task_credit.rs", "task_cleanup_start_releases_early", "self.phase = Phase::Cleaning;", "self.phase = Phase::Cleaned;"),
    ("task_credit.rs", "task_cleanup_finish_denies_release", "self.phase = Phase::Cleaned;", "self.phase = Phase::Cleaning;"),
    ("task_credit.rs", "task_cleanup_finishes_without_start", "if !matches!(self.phase, Phase::Cleaning) { return false; }", "if false { return false; }"),
    ("task_credit.rs", "task_connection_releases_before_cleanup", "if !self.can_release() { return false; }\n        registry.release(&self.key)\n    }\n\n    pub fn release_worker", "registry.release(&self.key)\n    }\n\n    pub fn release_worker"),
    ("task_credit.rs", "task_worker_releases_before_cleanup", "if !self.can_release() { return false; }\n        registry.release(&self.key)\n    }\n}", "registry.release(&self.key)\n    }\n}"),
    ("task_credit.rs", "task_admission_overwrites_retained_slot", "before.entries()[issued.slot() as int] == 0,", "true,"),
    ("drain.rs", "drain_denies_open_capacity", "if self.closed { None } else", "if true { None } else"),
    ("drain.rs", "drain_admits_after_close", "if self.closed { None } else", "if false { None } else"),
    ("drain.rs", "drain_close_is_ignored", "{ self.closed = true; }", "{ }"),
    ("drain.rs", "drain_release_reopens", "{ self.registry.release(key) }", "{ self.closed = false; self.registry.release(key) }"),
    ("drain.rs", "drain_forgets_release", "{ self.registry.release(key) }", "{ false }"),
    ("read_buffer.rs", "read_buffer_ignores_limit", "if !self.is_empty() || bytes.len() > self.limit", "if !self.is_empty()"),
    ("read_buffer.rs", "read_buffer_overwrites_live_frame", "if !self.is_empty() || bytes.len() > self.limit", "if bytes.len() > self.limit"),
    ("read_buffer.rs", "read_buffer_undercharges_consumed_prefix", "{ self.bytes.len() }", "{ self.bytes.len() - self.offset }"),
    ("read_buffer.rs", "read_buffer_retains_consumed_frame", "self.bytes = Vec::new();", "// retain backing"),
    ("read_buffer.rs", "read_buffer_loses_read_position", "self.offset += count;", "self.offset = count;"),
    ("read_buffer.rs", "read_buffer_wrong_output_range", "self.offset, self.offset + count", "0, count"),
    ("mailbox.rs", "mailbox_cleanup_omits_transferred_charge", "let occupied = value.is_some();", "let occupied = false;"),
    ("mailbox.rs", "mailbox_cleanup_releases_on_extraction", "self.started = true;", "self.started = true; self.finished = true;"),
    ("mailbox.rs", "mailbox_cleanup_finishes_before_extraction", "if !self.started || self.finished", "if self.finished"),
    ("mailbox.rs", "mailbox_cleanup_loses_payload", "core::mem::swap(&mut out, &mut self.value);", "let _discarded = self.value.take();"),
    ("mailbox.rs", "mailbox_cleanup_hides_retained_charge", "{ if self.occupied && !self.finished { 1 } else { 0 } }", "{ 0 }"),
    ("mailbox.rs", "mailbox_sends_after_receiver_close", "if !self.sender_open || !self.receiver_open || self.value.is_some()", "if !self.sender_open || self.value.is_some()"),
    ("mailbox.rs", "mailbox_overwrites_full_slot", "if !self.sender_open || !self.receiver_open || self.value.is_some()", "if !self.sender_open || !self.receiver_open"),
    ("mailbox.rs", "mailbox_denies_valid_send", "if !self.sender_open || !self.receiver_open || self.value.is_some()", "if true"),
    ("mailbox.rs", "mailbox_loses_received_item", "core::mem::swap(&mut value, &mut self.value);", "let _discarded = self.value.take();"),
    ("mailbox.rs", "mailbox_reopens_sender", "{ self.sender_open = false; }", "{ self.sender_open = true; }"),
    ("mailbox.rs", "mailbox_close_keeps_pending_item", "let value = self.pop();", "let value = None;"),
    ("mailbox.rs", "mailbox_hides_sender_closure", "{ !self.sender_open || !self.receiver_open }", "{ !self.receiver_open }"),
    ("mailbox.rs", "mailbox_count_omits_live_item", "if self.item().is_some() { 1 } else { 0 }", "0"),
    ("frame_queue.rs", "encode_without_reservation", "if !self.reserved || self.queue.is_closed() || payload.len() > self.payload_limit", "if self.queue.is_closed() || payload.len() > self.payload_limit"),
    ("frame_queue.rs", "encode_above_queue_limit", "if !self.reserved || self.queue.is_closed() || payload.len() > self.payload_limit", "if !self.reserved || self.queue.is_closed()"),
    ("framing.rs", "understate_record_body_size", "self.contents().len() == self.payload().len() + 33,", "self.contents().len() == self.payload().len() + 32,"),
    ("buffer_accounting.rs", "omit_in_progress_encoding", "queue.encoding_and_queued_bound(encoding.len());", "queue.encoding_and_queued_bound(0);"),
    ("buffer_accounting.rs", "unreserved_encoding_in_combined_bound", "!queue.reserved() ==> encoding.len() == 0,", "true,"),
    ("frame_queue.rs", "queue_reservation_not_charged", "self.reserved = true;", "self.reserved = false;"),
    ("frame_queue.rs", "queue_push_steals_reserved_slot", "if self.reserved { return Err(item); }", "if false { return Err(item); }"),
    ("frame_queue.rs", "queue_finish_leaks_reservation", "{\n        self.reserved = false;", "{\n        self.reserved = true;"),
    ("frame_queue.rs", "queue_allows_oversize_encoding_bound", "requires self.valid(), encoding_bytes <= self.payload_limit() + 65,", "requires self.valid(), encoding_bytes <= self.payload_limit() + 66,"),
    ("frame_queue.rs", "frame_queue_ignores_payload_limit", "if item.0.bytes().len() > self.payload_limit + 65 { return Err(item); }", "if false { return Err(item); }"),
    ("frame_queue.rs", "frame_queue_snapshot_omits_records", "self.items().map(|i: int, item: (RecordFrame, T)| item.0)", "Seq::empty()"),
    ("frame_queue.rs", "frame_queue_understates_overhead", "+ encoding_bytes <= self.capacity() * (self.payload_limit() + 65),", "+ encoding_bytes <= self.capacity() * (self.payload_limit() + 64),"),
    ("frame_queue.rs", "frame_queue_loses_dequeued_job", "let out = self.queue.pop();", "let _out = self.queue.pop(); let out = None;"),
    ("frame_queue.rs", "frame_queue_denies_valid_job", "let out = self.queue.push(item);", "let out = Err(item);"),
    ("fixed_queue.rs", "queue_admits_after_close", "if self.closed || self.used == self.slots.len() { return Err(value); }", "if self.used == self.slots.len() { return Err(value); }"),
    ("fixed_queue.rs", "queue_reopens_when_drained", "self.used -= 1;", "self.used -= 1; self.closed = false;"),
    ("fixed_queue.rs", "queue_close_is_ignored", "{ self.closed = true; }", "{ }"),
    ("fixed_queue.rs", "queue_overwrites_full", "if self.closed || self.used == self.slots.len() { return Err(value); }", "if self.closed { return Err(value); }"),
    ("fixed_queue.rs", "queue_discards_oldest", "assert(value == Some(old(self).contents()[0]));", "assert(value == Some(old(self).contents()[0])); value = None;"),
    ("fixed_queue.rs", "queue_does_not_advance", "self.head = if self.head == self.slots.len() - 1 { 0 } else { self.head + 1 };", "self.head = self.head;"),
    ("fixed_queue.rs", "queue_denies_valid_push", "if self.closed || self.used == self.slots.len() { return Err(value); }", "if true { return Err(value); }"),
    ("owned_accounting.rs", "owned_reserve_live_slot", "slots[index] == 0, id != 0,", "id != 0,"),
    ("owned_accounting.rs", "owned_replacement_wrong_owner", "slots[index] != 0, replacement.key().id() == slots[index], replacement.state().capacity() <= capacity,", "slots[index] != 0, replacement.state().capacity() <= capacity,"),
    ("owned_accounting.rs", "owned_total_omits_pending_read", "Some(o) => o.state().body() + o.read_bytes(),", "Some(o) => o.state().body(),"),
    ("owned_accounting.rs", "owned_replacement_ignores_capacity", "replacement.state().capacity() <= capacity,", "true,"),
    ("owned_accounting.rs", "owned_retirement_retains_payload", "ensures owners_match(slots.update(index, 0), owners.update(index, None), capacity),", "ensures owners_match(slots.update(index, 0), owners, capacity),"),
    ("owned_stream.rs", "read_keeps_completed_chunk", "if !self.stream.discard_completed() { return false; }", "if self.stream.is_closed() { return false; }"),
    ("owned_stream.rs", "read_changes_filled_prefix", "bytes.truncate(length);", "bytes.truncate(0);"),
    ("owned_stream.rs", "read_denies_valid_completion", "self.stream.advance(bytes).is_some()", "false"),
    ("buffer_accounting.rs", "omit_receipt_storage", "+ byte_sum(receipt_bytes(self.receipts)) + byte_sum(self.headers)", "+ byte_sum(self.headers)"),
    ("buffer_accounting.rs", "underbudget_output_cleanup", "+ (connections + 2 * requests) * 16384 + (queue + requests + MAX_BATCH as nat) * (chunk + 65)", "+ (connections + requests) * 16384 + (queue + requests + MAX_BATCH as nat) * (chunk + 65)"),
    ("buffer_accounting.rs", "underbudget_receipts", "+ (connections + 2 * requests) * 16384 + (queue + requests + MAX_BATCH as nat) * (chunk + 65)", "+ (connections + 2 * requests) * 16384 + (queue + MAX_BATCH as nat) * (chunk + 65)"),
    ("journal.rs", "receipt_frame_overhead_too_small", "ensures self.record().len() == self.payload_len() + 65,", "ensures self.record().len() == self.payload_len() + 64,"),
    ("owned_stream.rs", "owned_retirement_skips_release", "{ registry.release_stream(&self.key, self.stream) }", "{ true }"),
    ("owned_stream.rs", "owned_advance_changes_bytes", "let out = self.stream.advance(bytes);", "let out = self.stream.advance(Vec::new());"),
    ("owned_stream.rs", "owned_cancel_ignored", "{ self.stream.cancel() }", "{ }"),
    ("owned_stream.rs", "owned_prepare_denies_progress", "{ self.stream.prepare(max) }", "{ None }"),
    ("audit_journal.rs", "ledger_drops_frame", "self.frames = Ghost(self.frames@.push(saved));", ""),
    ("audit_journal.rs", "ledger_reverses_order", "self.frames = Ghost(self.frames@.push(saved));", "self.frames = Ghost(seq![saved] + self.frames@);"),
    ("audit_journal.rs", "ledger_denies_valid_commit", "let ghost saved = frame;", "if true { return None; } let ghost saved = frame;"),

    ("recovery.rs", "scanner_wrong_payload", "Some(record) => Ok(Some(record)),", "Some(mut record) => { record.bytes = Vec::new(); Ok(Some(record)) },"),
    ("recovery.rs", "scanner_wrong_header_extent", "self.source.read_exact(33)", "self.source.read_exact(34)"),
    ("recovery.rs", "scanner_ignores_checksum", "let checked = self.source.checksum_valid(header.as_slice(), bytes.as_slice(), checksum.as_slice());", "let checked = true;"),
    ("recovery.rs", "scanner_ignores_session_checksum", "let checked = source.checksum_valid(prefix, empty.as_slice(), checksum);", "let checked = true;"),

    ("framing.rs", "session_wrong_identity", "let session = [bytes[8], bytes[9]", "let session = [bytes[9], bytes[9]"),
    ("framing.rs", "session_wrong_version", " || bytes[7] != 49", ""),
    ("framing.rs", "session_ignores_checksum", "if !checksum_valid || bytes.len() != 24", "if bytes.len() != 24"),

    ("stream.rs", "deny_matching_receipt", "if !receipt.matches_record(header, bytes)", "if true"),
    ("framing.rs", "receipt_ignores_payload", "let payload_ok = equal_bytes(slice_subrange(bytes, 33, bytes.len() - 32), payload);", "let payload_ok = true;"),
    ("framing.rs", "equal_bytes_keeps_only_the_last_byte", "        let next = diff | (x ^ y);", "        let next = x ^ y;"),
    ("framing.rs", "receipt_ignores_header", "let header_ok = equal_bytes(slice_subrange(bytes, 0, 33), header.as_slice());", "let header_ok = true;"),
    ("stream.rs", "acknowledge_unmatched_receipt", "if !receipt.matches_record(header, bytes)", "if false"),
    ("journal.rs", "mint_receipt_without_commit", "if !self.record_durable(t, frame.bytes())", "if false"),

    ("framing.rs", "omit_sealed_checksum", "append(&mut self.bytes, checksum.as_slice());", ""),
    ("framing.rs", "discard_sealed_record", "RecordFrame { bytes: self.bytes,", "RecordFrame { bytes: Vec::new(),"),
    ("journal.rs", "deny_valid_typed_commit", "if !self.record_durable(t, frame.bytes()) { return None; }", "if true { return None; }"),

    ("stream.rs", "audit_wrong_authority", " || self.owner != authority.request_id()", ""),
    ("stream.rs", "audit_wrong_tenant", "tenant: authority.tenant_id(),", "tenant: 0,"),
    ("stream.rs", "audit_wrong_chunk", "request: self.owner, chunk: self.chunk, kind: direction", "request: self.owner, chunk: 0, kind: direction"),
    ("stream.rs", "audit_wrong_bytes", "kind: direction }, self.bytes.as_slice()", "kind: direction }, slice_subrange(self.bytes.as_slice(), 0, 0)"),

    ("journal.rs", "durable_commit_without_sync", "let _synced = self.sync_succeeded();", "let _synced = true;"),
    ("journal.rs", "durable_commit_without_ack", "let _acknowledged = self.acknowledge(t);", "let _acknowledged = true;"),
    ("journal.rs", "durable_commit_skips_prior_ack", " || self.acknowledged != self.written", ""),

    ("resource.rs", "release_wrong_stream", " || stream.owner_id() != key.id", ""),
    ("resource.rs", "release_unclaimed_stream", "if !key.stream_claimed || stream.owner_id() != key.id", "if stream.owner_id() != key.id"),
    ("resource.rs", "deny_owned_stream_retirement", "if !key.stream_claimed || stream.owner_id() != key.id", "if true"),
    ("stream.rs", "wrong_stream_owner_accessor", "ensures out == self.owner(),\n    { self.owner }", "ensures out == self.owner(),\n    { 0 }"),
    ("framing.rs", "deny_valid_recovered_record", "if !checksum_valid { return None; }", "if true { return None; }"),
    ("framing.rs", "deny_complete_frame", "if !self.stopped || ticket.start != self.offset { return false; }", "if true { return false; }"),
    ("framing.rs", "ignore_record_checksum", "if !checksum_valid { return None; }", ""),
    ("framing.rs", "recover_wrong_payload_extent", "if fields.payload as usize != bytes.len() { return None; }", ""),
    ("framing.rs", "discard_recovered_payload", "RecoveredRecord { header: fields, bytes }", "RecoveredRecord { header: fields, bytes: Vec::new() }"),
    ("journal.rs", "deny_valid_append", "if self.failed || self.pending != 0 || length == 0 || length > u64::MAX - self.written", "if true"),
    ("journal.rs", "deny_written_record", "if self.failed || t.session != self.session || t.start != self.written || t.end != self.pending", "if true || t.start != self.written || t.end != self.pending"),
    ("journal.rs", "deny_ready_sync", "if self.failed || self.pending != 0 { return false; }", "if true { return false; }"),
    ("journal.rs", "deny_durable_ack", "if self.failed || t.session != self.session || t.start != self.acknowledged || t.end <= t.start || self.durable < t.end", "if true"),
    ("resource.rs", "ignore_combined_budget", "total <= 134217728", "true"),
    ("resource.rs", "allow_zero_request_budget", "requests == 0 || ", ""),
    ("resource.rs", "hide_active_requests", "(active, self.slots.len())", "(0, self.slots.len())"),
    ("resource.rs", "count_empty_slots", "if self.slots[i] != 0 { active = active + 1; }", "if self.slots[i] == 0 { active = active + 1; }"),
    ("stream.rs", "deny_valid_ack", "if self.closed || self.failed || owner != self.owner || chunk != self.chunk\n            || end < self.logged || end > self.bytes.len() { return false; }", "if true { return false; }"),
    ("stream.rs", "deny_ready_write", "if self.closed || self.pending || max == 0 || self.generation == u64::MAX", "if true"),
    ("stream.rs", "deny_valid_completion", GUARD, "if true"),
    ("stream.rs", "deny_ready_chunk", "if self.closed || self.pending || self.sent != self.bytes.len()\n            || bytes.len() > self.capacity || self.chunk == u64::MAX { return None; }", "if true { return None; }"),
    ("stream.rs", "deny_completed_discard", "if self.closed || self.pending || self.bytes.len() != self.sent { return false; }", "if true { return false; }"),
    ("resource.rs", "deny_valid_release", "if key.slot >= self.slots.len() || key.id == 0 || self.slots[key.slot] != key.id {\n            return false;\n        }", "if true { return false; }"),
    ("resource.rs", "deny_free_capacity", "if self.next == u64::MAX { return None; }", "if true { return None; }"),
    ("resource.rs", "deny_valid_stream", "if key.stream_claimed || key.id != authority.request_id() { return None; }", "if true { return None; }"),
    ("framing.rs", "wrong_payload_length", "if h.payload as usize != payload.len() { return None; }", ""),
    ("framing.rs", "omit_framed_payload", "append(&mut bytes, payload);", ""),
    ("resource.rs", "bind_wrong_authority", " || key.id != authority.request_id()", ""),
    ("resource.rs", "duplicate_admitted_stream", "if key.stream_claimed || ", "if "),
    ("resource.rs", "wrong_stream_owner", "StreamChunk::new(key.id, Vec::new(), capacity, strict)", "StreamChunk::new(0, Vec::new(), capacity, strict)"),
    ("stream.rs", "discard_unsent_payload", " || self.bytes.len() != self.sent", ""),
    ("stream.rs", "retain_completed_payload", "self.bytes = Vec::new();", ""),
    ("framing.rs", "restart_stopped_scan", "if self.stopped { return None; }", "if false { return None; }"),
    ("framing.rs", "advance_before_validation", "self.stopped = true;", "self.stopped = true; self.offset = 0;"),
    ("framing.rs", "scan_offset_regression", "self.offset = end;", "self.offset = 0;"),
    ("framing.rs", "decode_wrong_request", "let request = u64_from_le_bytes(slice_subrange(bytes, 16, 24));", "let request = u64_from_le_bytes(slice_subrange(bytes, 8, 16));"),
    ("framing.rs", "unbounded_payload", "if payload > 1048576 || request == 0 || kind > 4", "if request == 0 || kind > 4"),
    ("framing.rs", "accept_incomplete_frame", "available < length || ", ""),
    ("framing.rs", "skip_frame_byte", "Some(start + length)", "Some(start + length - 1)"),
    ("journal.rs", "ack_before_sync", " || self.durable < t.end", ""),
    ("journal.rs", "replace_pending_append", "self.failed || self.pending != 0 || length == 0", "self.failed || length == 0"),
    ("journal.rs", "wrong_record_length", " || bytes.len() as u64 != t.end - t.start", ""),
    ("journal.rs", "skip_synced_prefix", "self.durable = self.written;", "self.durable = 0;"),
    ("stream.rs", "wrong_log_payload", "{ self.bytes.as_slice() }", "{ slice_subrange(self.bytes.as_slice(), 0, 0) }"),
    ("stream.rs", "hide_closed_stream", "ensures out == self.closed(),\n    { self.closed }", "ensures out == self.closed(),\n    { false }"),
    ("stream.rs", "replace_unfinished", "self.sent != self.bytes.len()", "false"),
    ("stream.rs", "stale_log_ack", " || chunk != self.chunk", ""),
    ("stream.rs", "before_durable", "let limit = if self.strict { self.logged } else { self.bytes.len() };", "let limit = self.bytes.len();"),
    ("stream.rs", "wrong_owner", GUARD, GUARD.replace(" || t.owner != self.owner", "")),
    ("stream.rs", "stale_completion", GUARD, GUARD.replace(" || t.generation != self.generation", "")),
    ("stream.rs", "pretend_full_write", "self.sent = self.sent + count;", "self.sent = self.offered;"),
    ("stream.rs", "wrong_slice", "slice_subrange(self.bytes.as_slice(), self.sent, self.offered)", "slice_subrange(self.bytes.as_slice(), 0, self.offered)"),
    ("stream.rs", "ignore_cancellation", "if self.closed || self.pending || max == 0 || self.generation == u64::MAX", "if self.pending || max == 0 || self.generation == u64::MAX"),
    ("resource.rs", "release_claimed_reservation", "if key.stream_claimed { return false; }", "if false { return false; }"),
    ("resource.rs", "evict_live_request", "if self.slots[i] == 0 {", "if true {"),
    ("resource.rs", "reuse_id", "self.next = self.next + 1;", "self.next = self.next;"),
    ("resource.rs", "change_budget", "let id = self.next;", "let id = self.next; self.per_request = 0;"),
    ("resource.rs", "stale_release", """if key.slot >= self.slots.len() || key.id == 0 || self.slots[key.slot] != key.id {
            return false;
        }""", """if key.slot >= self.slots.len() || key.id == 0 {
            return false;
        }"""),
    ("policy.rs", "unauthenticated_identity", "if equal_bytes(self.identities[i].digest.as_slice(), digest) {", "if true {"),
    ("policy.rs", "cross_tenant_route", "if r.tenant == self.tenant && r.selector == selector {", "if r.selector == selector {"),
    ("policy.rs", "expand_root_grants", " || !root_contains(&grants, route)", ""),
    ("policy.rs", "erase_validated_root_snapshot", "grants: Ghost(grants@)", "grants: Ghost(Seq::empty())"),
    ("policy.rs", "erase_validated_credential_snapshot", "credential_tenants: Ghost(credential_tenants@)", "credential_tenants: Ghost(Seq::empty())"),
    ("policy.rs", "cross_tenant_credential", "credential_tenants[route.credential] != route.tenant", "false"),
    ("policy.rs", "unknown_origin", "route.origin >= origin_count", "false"),
    ("policy.rs", "wrong_dispatch_origin", "Route { tenant: r.tenant, selector: r.selector, origin: r.origin, credential: r.credential }", "Route { tenant: r.tenant, selector: r.selector, origin: 0, credential: r.credential }"),
    ("policy.rs", "ambiguous_identity", "|| equal_bytes(identities[j].digest.as_slice(), identities[i].digest.as_slice())", ""),
    # Record kinds: framing admits kinds 0..=4; body-write evidence stays at 0..=1;
    # body chunks never use the metadata chunk id 0.
    ("framing.rs", "encode_accepts_unknown_kind", "if h.payload > 1048576 || h.request == 0 || h.kind > 4 { return None; }", "if h.payload > 1048576 || h.request == 0 { return None; }"),
    ("framing.rs", "decode_accepts_unknown_kind", "if payload > 1048576 || request == 0 || kind > 4 { return None; }", "if payload > 1048576 || request == 0 { return None; }"),
    ("framing.rs", "encode_drops_kind_byte", "    bytes.push(h.kind);", "    bytes.push(0);"),
    ("stream.rs", "audit_accepts_metadata_kind", "            || direction > 1 { return None; }", "            || direction > 4 { return None; }"),
    ("stream.rs", "audit_uses_metadata_chunk", "if self.closed || self.failed || self.owner == 0 || self.chunk == 0", "if self.closed || self.failed || self.owner == 0"),
    ("submission.rs", "direction_widens_prepare_to_metadata_kinds", "if direction > 1 { return None; }", "if direction > 4 { return None; }"),
    ("submission.rs", "direction_widens_bytes_to_metadata_kinds", "if direction > 1 || self.direction != direction { return None; }", "if direction > 4 || self.direction != direction { return None; }"),

    # Metadata codecs: every length check and every field of each payload.
    ("metadata.rs", "request_start_encodes_empty_destination", "if destination.len() == 0 || destination.len() > 8192 { return None; }", "if destination.len() > 8192 { return None; }"),
    ("metadata.rs", "request_start_encodes_oversized_destination", "if destination.len() == 0 || destination.len() > 8192 { return None; }", "if destination.len() == 0 { return None; }"),
    ("metadata.rs", "request_start_encode_wrong_time", "let mut bytes = Vec::with_capacity(18 + destination.len());\n    append(&mut bytes, u64_to_le_bytes(time_ms).as_slice());", "let mut bytes = Vec::with_capacity(18 + destination.len());\n    append(&mut bytes, u64_to_le_bytes(0).as_slice());"),
    ("metadata.rs", "request_start_encode_wrong_selector", "append(&mut bytes, u64_to_le_bytes(selector).as_slice());", "append(&mut bytes, u64_to_le_bytes(0).as_slice());"),
    ("metadata.rs", "request_start_encode_wrong_length", "append(&mut bytes, u16_to_le_bytes(destination.len() as u16).as_slice());", "append(&mut bytes, u16_to_le_bytes(1).as_slice());"),
    ("metadata.rs", "request_start_encode_omits_destination", "    append(&mut bytes, destination);\n", ""),
    ("metadata.rs", "request_start_decode_accepts_empty", "if length == 0 || length > 8192 || bytes.len() != 18 + length as usize { return None; }", "if length > 8192 || bytes.len() != 18 + length as usize { return None; }"),
    ("metadata.rs", "request_start_decode_accepts_oversized", "if length == 0 || length > 8192 || bytes.len() != 18 + length as usize { return None; }", "if length == 0 || bytes.len() != 18 + length as usize { return None; }"),
    ("metadata.rs", "request_start_decode_ignores_declared_length", "if length == 0 || length > 8192 || bytes.len() != 18 + length as usize { return None; }", "if length == 0 || length > 8192 || bytes.len() < 18 + length as usize { return None; }"),
    ("metadata.rs", "request_start_decode_wrong_time", "if length == 0 || length > 8192 || bytes.len() != 18 + length as usize { return None; }\n    let time_ms = u64_from_le_bytes(slice_subrange(bytes, 0, 8));", "if length == 0 || length > 8192 || bytes.len() != 18 + length as usize { return None; }\n    let time_ms = u64_from_le_bytes(slice_subrange(bytes, 8, 16));"),
    ("metadata.rs", "request_start_decode_wrong_selector", "let selector = u64_from_le_bytes(slice_subrange(bytes, 8, 16));", "let selector = u64_from_le_bytes(slice_subrange(bytes, 0, 8));"),
    ("metadata.rs", "request_start_decode_truncates_destination", "let destination = slice_to_vec(slice_subrange(bytes, 18, bytes.len()));", "let destination = slice_to_vec(slice_subrange(bytes, 18, 19));"),
    ("metadata.rs", "response_head_encodes_status_below_100", "if status < 100 || status > 999 { return None; }\n    proof", "if status > 999 { return None; }\n    proof"),
    ("metadata.rs", "response_head_encodes_status_above_999", "if status < 100 || status > 999 { return None; }\n    proof", "if status < 100 { return None; }\n    proof"),
    ("metadata.rs", "response_head_encode_wrong_time", "let mut bytes = Vec::with_capacity(10);\n    append(&mut bytes, u64_to_le_bytes(time_ms).as_slice());", "let mut bytes = Vec::with_capacity(10);\n    append(&mut bytes, u64_to_le_bytes(0).as_slice());"),
    ("metadata.rs", "response_head_encode_wrong_status", "append(&mut bytes, u16_to_le_bytes(status).as_slice());", "append(&mut bytes, u16_to_le_bytes(200).as_slice());"),
    ("metadata.rs", "response_head_decode_wrong_length", "if bytes.len() != 10 { return None; }", "if bytes.len() < 10 { return None; }"),
    ("metadata.rs", "response_head_decode_accepts_status_below_100", "if status < 100 || status > 999 { return None; }\n    let time_ms", "if status > 999 { return None; }\n    let time_ms"),
    ("metadata.rs", "response_head_decode_accepts_status_above_999", "if status < 100 || status > 999 { return None; }\n    let time_ms", "if status < 100 { return None; }\n    let time_ms"),
    ("metadata.rs", "response_head_decode_wrong_status", "let status = u16_from_le_bytes(slice_subrange(bytes, 8, 10));", "let status = u16_from_le_bytes(slice_subrange(bytes, 0, 2));"),
    ("metadata.rs", "response_head_decode_wrong_time", "if status < 100 || status > 999 { return None; }\n    let time_ms = u64_from_le_bytes(slice_subrange(bytes, 0, 8));", "if status < 100 || status > 999 { return None; }\n    let time_ms = u64_from_le_bytes(slice_subrange(bytes, 2, 10));"),
    ("metadata.rs", "completion_encodes_unknown_outcome", "if outcome > 7 { return None; }\n    proof", "if outcome > 8 { return None; }\n    proof"),
    ("metadata.rs", "completion_encode_wrong_time", "let mut bytes = Vec::with_capacity(25);\n    append(&mut bytes, u64_to_le_bytes(time_ms).as_slice());", "let mut bytes = Vec::with_capacity(25);\n    append(&mut bytes, u64_to_le_bytes(0).as_slice());"),
    ("metadata.rs", "completion_encode_wrong_outcome", "    bytes.push(outcome);", "    bytes.push(0);"),
    ("metadata.rs", "completion_encode_wrong_upload", "append(&mut bytes, u64_to_le_bytes(upload_bytes).as_slice());", "append(&mut bytes, u64_to_le_bytes(0).as_slice());"),
    ("metadata.rs", "completion_encode_wrong_download", "append(&mut bytes, u64_to_le_bytes(download_bytes).as_slice());", "append(&mut bytes, u64_to_le_bytes(0).as_slice());"),
    ("metadata.rs", "completion_decode_wrong_length", "if bytes.len() != 25 { return None; }", "if bytes.len() < 25 { return None; }"),
    ("metadata.rs", "completion_decode_accepts_unknown_outcome", "let outcome = bytes[8];\n    if outcome > 7 { return None; }", "let outcome = bytes[8];\n    if outcome > 8 { return None; }"),
    ("metadata.rs", "completion_decode_wrong_time", "if outcome > 7 { return None; }\n    let time_ms = u64_from_le_bytes(slice_subrange(bytes, 0, 8));", "if outcome > 7 { return None; }\n    let time_ms = u64_from_le_bytes(slice_subrange(bytes, 9, 17));"),
    ("metadata.rs", "completion_decode_wrong_outcome", "Some(Completion { time_ms, outcome, upload_bytes, download_bytes })", "Some(Completion { time_ms, outcome: 0, upload_bytes, download_bytes })"),
    ("metadata.rs", "completion_decode_wrong_upload", "let upload_bytes = u64_from_le_bytes(slice_subrange(bytes, 9, 17));", "let upload_bytes = u64_from_le_bytes(slice_subrange(bytes, 17, 25));"),
    ("metadata.rs", "completion_decode_wrong_download", "let download_bytes = u64_from_le_bytes(slice_subrange(bytes, 17, 25));", "let download_bytes = u64_from_le_bytes(slice_subrange(bytes, 9, 17));"),

    # Shipper core: tailing scanner, exchange assembly, batch limits, upload
    # progress, identities, and enrollment.
    ("recovery.rs", "scanner_resume_ignores_offset", "Scanner { source, cursor: Cursor::new(offset), session, start: Ghost(offset)", "Scanner { source, cursor: Cursor::new(56), session, start: Ghost(offset)"),
    ("recovery.rs", "records_from_drops_record", "        seq![record_at(data, start)] + records_from::<R>(data, record_end(data, start))", "        records_from::<R>(data, record_end(data, start))"),
    ("recovery.rs", "record_at_wrong_payload_start", "        data.subrange(start as int + 33, record_end(data, start) as int - 32))", "        data.subrange(start as int + 32, record_end(data, start) as int - 32))"),
    ("recovery.rs", "emission_step_forgets_record", "            Ok(Some(record)) => after.emitted() == before.emitted().push((record.header, record.bytes@)),", "            Ok(Some(record)) => after.emitted() == before.emitted(),"),
    ("recovery.rs", "scan_end_stays_put", "    if complete_record::<R>(data, start) { scan_end::<R>(data, record_end(data, start)) } else { start }", "    start"),
    ("exchange_assembler.rs", "assembler_forgets_truncation", "let take = if payload.len() <= room { payload.len() } else { self.truncated = true; room };", "let take = if payload.len() <= room { payload.len() } else { room };"),
    ("exchange_assembler.rs", "assembler_keeps_bytes_beyond_cap", "let kept = slice_subrange(payload, 0, take);", "let kept = payload;"),
    ("exchange_assembler.rs", "assembler_appends_out_of_order", "let ghost before = self.upload@;\n            let ghost all = self.upload_all@;\n            append(&mut self.upload, kept);", "let ghost before = self.upload@;\n            let ghost all = self.upload_all@;\n            let mut swapped = vstd::slice::slice_to_vec(kept); append(&mut swapped, self.upload.as_slice()); self.upload = swapped;"),
    ("exchange_assembler.rs", "assembler_total_ignores_dropped_bytes", "self.download_total = saturating_add(self.download_total, payload.len() as u64);", "self.download_total = saturating_add(self.download_total, take as u64);"),
    ("exchange_assembler.rs", "assembler_never_evicts_at_capacity", "None => if self.open.len() == self.max_open { self.evict_oldest() } else { None },", "None => None,"),
    ("exchange_assembler.rs", "assembler_duplicate_start_keeps_both", "                    let mut e = self.take(index); e.incomplete = true; Some(e)", "                    None"),
    ("exchange_assembler.rs", "assembler_restart_not_marked_incomplete", "                    let mut e = self.take(index); e.incomplete = true; Some(e)", "                    let e = self.take(index); Some(e)"),
    ("exchange_assembler.rs", "assembler_completion_leaves_request_open", "                if header.kind == 4 {\n                    let mut e = self.take(index);", "                if header.kind == 5 {\n                    let mut e = self.take(index);"),
    ("exchange_assembler.rs", "assembler_orphan_not_marked", "let mut e = Exchange::open(header.tenant, header.request, None, true);", "let mut e = Exchange::open(header.tenant, header.request, None, false);"),
    ("exchange_assembler.rs", "assembler_eviction_not_marked_incomplete", "        let mut out = self.take(0);\n        out.incomplete = true;\n        proof { assert(before.remove(0) =~= before.drop_first()); }\n        Some(out)", "        let out = self.take(0);\n        proof { assert(before.remove(0) =~= before.drop_first()); }\n        Some(out)"),
    ("exchange_assembler.rs", "assembler_find_returns_wrong_request", "if self.open[i].request == request { return Some(i); }", "if true { return Some(i); }"),
    ("exchange_assembler.rs", "assembler_new_accepts_zero_capacity", "        requires 0 < max_open,\n        ensures out.valid()", "        requires 0 <= max_open,\n        ensures out.valid()"),
    ("exchange_assembler.rs", "saturating_add_wraps", "if a > u64::MAX - b { u64::MAX } else { a + b }", "if a > u64::MAX - b { 0 } else { a + b }"),
    ("shipping_identity.rs", "exchange_key_drops_session", "    let mut bytes = Vec::with_capacity(24);\n    append(&mut bytes, session.as_slice());\n", "    let mut bytes = Vec::with_capacity(24);\n"),
    ("shipping_identity.rs", "part_key_repeats_message", "    append(&mut bytes, u32_to_le_bytes(part).as_slice());", "    append(&mut bytes, u32_to_le_bytes(message).as_slice());"),
    ("shipping_identity.rs", "batch_id_ignores_first", "    append(&mut bytes, u64_to_le_bytes(first).as_slice());\n    append(&mut bytes, u64_to_le_bytes(end).as_slice());", "    append(&mut bytes, u64_to_le_bytes(0).as_slice());\n    append(&mut bytes, u64_to_le_bytes(end).as_slice());"),
    ("shipping_identity.rs", "part_key_encoding_ignores_part", "message_key_encoding(session, request, message) + spec_u32_to_le_bytes(part)", "message_key_encoding(session, request, message) + spec_u32_to_le_bytes(0)"),
    ("shipping_identity.rs", "hex_swaps_nibbles", "        out.push(digit(b / 16));\n        out.push(digit(b % 16));", "        out.push(digit(b % 16));\n        out.push(digit(b / 16));"),
    ("shipping_identity.rs", "hex_wrong_letter_offset", "    if n < 10 { 48 + n } else { 87 + n }", "    if n < 10 { 48 + n } else { 86 + n }"),
    ("shipping_identity.rs", "hex_encoding_drops_low_nibble", "if i % 2 == 0 { hex_digit(s[i / 2] as int / 16) } else { hex_digit(s[i / 2] as int % 16) }", "if i % 2 == 0 { hex_digit(s[i / 2] as int / 16) } else { hex_digit(0) }"),
    ("shipping_identity.rs", "hex_digit_collides", "    if n < 10 { (48 + n) as u8 } else { (87 + n) as u8 }", "    if n < 10 { (48 + n) as u8 } else { (38 + n) as u8 }"),
    ("shipping_identity.rs", "batch_id_encoding_ignores_checksum", "session + spec_u64_to_le_bytes(first) + spec_u64_to_le_bytes(end) + spec_u64_to_le_bytes(checksum)", "session + spec_u64_to_le_bytes(first) + spec_u64_to_le_bytes(end) + spec_u64_to_le_bytes(0)"),
    ("batch_builder.rs", "batch_exceeds_row_limit", "if self.rows >= MAX_ROWS || row.len() >= MAX_BYTES - self.body.len() { return false; }", "if row.len() >= MAX_BYTES - self.body.len() { return false; }"),
    ("batch_builder.rs", "batch_exceeds_byte_limit", "if self.rows >= MAX_ROWS || row.len() >= MAX_BYTES - self.body.len() { return false; }", "if self.rows >= MAX_ROWS || row.len() > MAX_BYTES - self.body.len() { return false; }"),
    ("batch_builder.rs", "batch_drops_newline", "        append(&mut self.body, row);\n        self.body.push(10);", "        append(&mut self.body, row);"),
    ("batch_builder.rs", "batch_finish_keeps_row_count", "        core::mem::swap(&mut body, &mut self.body);\n        self.rows = 0;", "        core::mem::swap(&mut body, &mut self.body);"),
    ("batch_builder.rs", "batch_oversized_off_by_one", "{ row.len() >= MAX_BYTES }", "{ row.len() > MAX_BYTES }"),
    ("upload_cursor.rs", "cursor_acknowledges_any_id", "Some(b) => equal_bytes(b.id.as_slice(), id), None => false };", "Some(_) => true, None => false };"),
    ("upload_cursor.rs", "cursor_acknowledge_resolves_wrong_end", "        let batch = self.in_flight.take().unwrap();\n        self.resolved = batch.end;", "        let batch = self.in_flight.take().unwrap();\n        self.resolved = batch.first;"),
    ("upload_cursor.rs", "cursor_opens_second_batch", "if self.in_flight.is_some() || count == 0 || count > self.emitted - self.resolved { return false; }", "if count == 0 || count > self.emitted - self.resolved { return false; }"),
    ("upload_cursor.rs", "cursor_opens_beyond_emitted", "if self.in_flight.is_some() || count == 0 || count > self.emitted - self.resolved { return false; }", "if self.in_flight.is_some() || count == 0 { return false; }"),
    ("upload_cursor.rs", "cursor_batch_id_uses_wrong_first", "let id = batch_id(session, self.resolved, self.resolved + count, checksum);", "let id = batch_id(session, self.emitted, self.resolved + count, checksum);"),
    ("upload_cursor.rs", "cursor_abandon_resolves", "    { self.in_flight = None; }", "    { if let Some(b) = self.in_flight.take() { self.resolved = b.end; } }"),
    ("upload_cursor.rs", "cursor_restore_accepts_inverted_counts", "        if resolved > emitted { return None; }\n", ""),
    ("upload_cursor.rs", "cursor_poison_keeps_place", "        let Some(batch) = self.in_flight.take() else { return false; };\n        self.resolved = batch.end;", "        let Some(batch) = self.in_flight.take() else { return false; };\n        self.resolved = batch.first;"),
    ("enrollment.rs", "enrollment_uploads_when_expired", "match self.state { State::Enrolled { expires_at } => now < expires_at, _ => false }", "match self.state { State::Enrolled { expires_at } => true, _ => false }"),
    ("enrollment.rs", "enrollment_refreshes_in_a_loop", "if !self.refreshed_after_rejection { self.refreshed_after_rejection = true; return Recovery::Refresh; }", "if !self.refreshed_after_rejection { return Recovery::Refresh; }"),
    ("enrollment.rs", "enrollment_revives_after_stop", "if matches!(self.state, State::Stopped) || now >= expires_at { return false; }", "if now >= expires_at { return false; }"),
    ("enrollment.rs", "enrollment_accepts_expired_token", "if matches!(self.state, State::Stopped) || now >= expires_at { return false; }", "if matches!(self.state, State::Stopped) { return false; }"),
    ("enrollment.rs", "enrollment_revoke_not_absorbing", "    { self.state = State::Stopped; }", "    { self.state = State::Unenrolled; }"),
    ("enrollment.rs", "enrollment_rejected_ignores_stop", "        if matches!(self.state, State::Stopped) { return Recovery::Stop; }\n", ""),
    ("enrollment.rs", "enrollment_refresh_window_only_after_expiry", "State::Enrolled { expires_at } => expires_at <= now || (!self.fresh && expires_at - now <= RENEWAL_WINDOW_SECONDS),", "State::Enrolled { expires_at } => expires_at <= now,"),
    ("enrollment.rs", "throttle_delay_unbounded", "if seconds > MAX_DELAY_SECONDS { MAX_DELAY_SECONDS } else { seconds }", "seconds"),
    ("enrollment.rs", "transport_delay_can_be_zero", "if attempt < 3 { 2 * (attempt as u64 + 1) }", "if attempt < 3 { 2 * (attempt as u64) }"),

    # Shipper machine: destination by type, token containment, conservation,
    # batch fidelity, bounded waiting, and progress.
    ("shipper.rs", "machine_refresh_leaks_token", "return Action::Send(Request { path: Path::Refresh, bearer: Some(bearer), body: Vec::new(), batch_id: None });", "return Action::Send(Request { path: Path::Refresh, bearer: Some(bearer), body: copy_bytes(self.token.as_slice()), batch_id: None });"),
    ("shipper.rs", "machine_ingest_skips_front_exchange", "        let mut body: Vec<u8> = Vec::new();\n        let mut i: usize = 0;", "        let mut body: Vec<u8> = Vec::new();\n        let mut i: usize = 1;"),
    ("shipper.rs", "machine_ingest_opens_wrong_range", "let _opened = self.cursor.open_batch(count as u64, &self.session, sum);", "let _opened = self.cursor.open_batch(1, &self.session, sum);"),
    ("shipper.rs", "machine_ack_pops_wrong_count", "                self.pop_front(count as usize);\n                self.enrollment.uploaded();", "                self.pop_front(1);\n                self.enrollment.uploaded();"),
    ("shipper.rs", "machine_ack_leaves_batch_in_flight", "                let _ok = self.cursor.acknowledge(id.as_slice());\n                proof { assert(_ok); self.cursor.bounds(); }\n", "                proof { self.cursor.bounds(); }\n"),
    ("shipper.rs", "machine_poison_keeps_exchange_queued", "                    proof { assert(_poisoned); self.cursor.bounds(); }\n                    self.pop_front(1);", "                    proof { assert(_poisoned); self.cursor.bounds(); }"),
    ("shipper.rs", "machine_enqueue_accepts_out_of_order", "if token.index != counted { return Err(token); }", ""),
    ("shipper.rs", "machine_enqueue_drops_body", "let pending = Pending { body, rows, source: Ghost(token.exchange.request_id()) };", "let pending = Pending { body: Vec::new(), rows, source: Ghost(token.exchange.request_id()) };"),
    ("shipper.rs", "machine_uploads_before_enrollment", "        if self.enrollment.needs_bootstrap() {\n            self.awaiting = Some(Path::Bootstrap);", "        if false {\n            self.awaiting = Some(Path::Bootstrap);"),
    ("shipper.rs", "machine_ignores_forced_refresh", "if self.force_refresh || self.enrollment.needs_refresh(now) {", "if self.enrollment.needs_refresh(now) {"),
    ("shipper.rs", "machine_throttle_can_be_zero", "        let delay = throttle_delay(self.throttle_attempt, retry_after);\n        self.throttle_attempt = bump(self.throttle_attempt);", "        let delay = 0;\n        self.throttle_attempt = bump(self.throttle_attempt);"),
    ("shipper.rs", "machine_revoke_keeps_credential", "        self.enrollment.revoked();\n        self.jwt = None;", "        self.enrollment.revoked();"),
    ("shipper.rs", "machine_runs_while_stopped", "        if self.enrollment.is_stopped() { return Action::Stopped; }\n", ""),
    ("shipper.rs", "machine_resends_checkpointed_exchanges", "        if index < self.skip { return None; }\n", ""),
    ("shipper.rs", "machine_reads_past_capacity", "!self.read_failed && !self.at_end && outstanding < self.max_open as u64 && self.queue.len() < self.max_open - outstanding as usize", "!self.read_failed && !self.at_end"),
    ("shipper.rs", "checksum_ignores_input", "        h = reduced as u64;", "        h = h;"),
    ("shipper.rs", "bootstrap_body_unescaped", "        if b == 34 || b == 92 { out.push(92); }\n", ""),
    ("shipper.rs", "machine_acknowledges_any_status", "            200 | 202 => {\n                let id = match", "            200 | 202 | 500 => {\n                let id = match"),
    ("shipper.rs", "machine_isolates_single_exchange", "                if count > 1 {\n                    self.cursor.abandon();", "                if count > 0 {\n                    self.cursor.abandon();"),
    ("shipper.rs", "machine_adopts_expired_credential", "                    if self.enrollment.enrolled(credential.expires_at, now) {", "                    if self.enrollment.enrolled(credential.expires_at, 0) {"),
    ("shipper.rs", "machine_sleep_keeps_delay", "            let d = self.delay;\n            self.delay = 0;", "            let d = self.delay;"),

    # Verified driver: every token is queued at once, headers are checked before
    # admission, reads and flushes respect the machine's limits, every send gets
    # its reply, and checkpoints carry the machine's own progress.
    ("shipping_driver.rs", "driver_drops_token", "                        Some(token) => settle(machine, effects, token),", "                        Some(_) => {}"),
    ("shipping_driver.rs", "driver_admits_unchecked_header", "if header_ok(&header, payload.len()) {", "if true {"),
    ("shipping_driver.rs", "driver_reads_when_unwanted", "    while count < PUMP_BATCH && machine.wants_records()\n", "    while count < PUMP_BATCH\n"),
    ("shipping_driver.rs", "driver_pump_ignores_batch_cap", "    while count < PUMP_BATCH && machine.wants_records()\n", "    while machine.wants_records()\n"),
    ("shipping_driver.rs", "driver_flushes_without_room", "while machine.open_exchanges() > 0 && machine.has_room()", "while machine.open_exchanges() > 0"),
    ("shipping_driver.rs", "driver_ignores_reply", "machine.reply(replied_at, reply)", "Outcome::Nothing"),
    ("exchange_assembler.rs", "emission_spec_evicts_newest", "else if open.len() == max_open { (open.drop_first().push(request), Some(open[0])) }", "else if open.len() == max_open { (open.drop_first().push(request), Some(open[open.len() - 1])) }"),
    ("shipper.rs", "machine_forgets_emission", "                self.emissions = Ghost(self.emissions@.push(exchange.request_id()));\n                proof { assert(self.emissions@.drop_last() =~= old(self).emissions@); }\n                self.number(exchange)\n            }\n        }\n    }\n\n    /// Emit the oldest open exchange", "                self.number(exchange)\n            }\n        }\n    }\n\n    /// Emit the oldest open exchange"),
    ("shipper.rs", "machine_records_wrong_source", "source: Ghost(token.exchange.request_id())", "source: Ghost(0)"),
    ("egress.rs", "egress_permit_forgets_tenant", "origin: Origin::Provider { tenant: authority.tenant_id(), origin: route.origin, credential: route.credential }", "origin: Origin::Provider { tenant: 0, origin: route.origin, credential: route.credential }"),
    ("egress.rs", "egress_permit_swaps_credential_index", "credential: route.credential } })", "credential: route.origin } })"),
    ('http1_head.rs', 'head_field_accepts_empty_name', 'if c == 0 || c >= line.len() || !all_tchar(line, 0, c) {', 'if c >= line.len() || !all_tchar(line, 0, c) {'),
    ('http1_head.rs', 'head_request_target_need_not_be_origin_form', 'if b >= line.len() || b == a + 1 || line[a + 1] != 47 || !all_vchar(line, a + 1, b)', 'if b >= line.len() || b == a + 1 || !all_vchar(line, a + 1, b)'),
    ('http1_head.rs', 'head_accepts_a_101st_field', '        if fields.len() == MAX_FIELDS {', '        if fields.len() == MAX_FIELDS + 1 {'),
    ('http1_head.rs', 'head_size_limit_off_by_two', '        if cursor > MAX_BYTES - 2 {', '        if cursor > MAX_BYTES {'),
    ('http1_head.rs', 'head_status_class_unchecked', '|| line[9] < 49 || line[9] > 53 ||', '|| line[9] < 48 || line[9] > 57 ||'),
    ('http1_head.rs', 'head_bare_lf_terminates_a_line', 'if p < buffer.len() && buffer[p] == LF {', 'if false {'),
    ('http1_head.rs', 'head_value_bytes_unchecked', '    if !all_value_bytes(line, s, e) {', '    if false {'),
    ('http1_write.rs', 'write_field_drops_the_space', '        out.push(COLON); out.push(SP);', '        out.push(COLON);'),
    ('http1_write.rs', 'wire_check_allows_uppercase_names', 'if !tchar(b) || (b >= 65 && b <= 90) { return false; }', 'if !tchar(b) { return false; }'),
    ('http1_write.rs', 'wire_check_allows_a_trailing_blank', 'if first == 32 || first == 9 || last == 32 || last == 9 { return false; }', 'if first == 32 || first == 9 { return false; }'),
    ('http1_framing.rs', 'framing_accepts_both_length_and_coding', 'if (te >= 1 && cl >= 1) || te > 1 || cl > 1 { return Err(Rejection::BadRequest); }', 'if te > 1 || cl > 1 { return Err(Rejection::BadRequest); }'),
    ('http1_framing.rs', 'canonical_decimal_accepts_leading_zeros', '    if value[0] == 48 && value.len() > 1 {', '    if false {'),
    ('http1_chunked.rs', 'chunked_size_accepts_seventeen_digits', 'if self.digits >= MAX_SIZE_DIGITS { return self.reject(); }', 'if self.digits > MAX_SIZE_DIGITS { return self.reject(); }'),
    ('http1_chunked.rs', 'chunked_last_cr_skips_the_lf', '        self.phase = Phase::LastLf;\n', '        self.phase = Phase::Done;\n'),
    ('http1_chunked.rs', 'chunked_data_count_off_by_one', 'else { self.phase = Phase::Data; self.remaining = self.size; }', 'else { self.phase = Phase::Data; self.remaining = self.size - 1; }'),
    ('http1_chunked.rs', 'chunked_data_never_ends', '        if self.remaining == 0 { self.phase = Phase::DataCr; }\n', ''),
    ('http1_chunked.rs', 'chunked_last_chunk_drops_a_byte', '    out.push(48); out.push(CR); out.push(LF); out.push(CR); out.push(LF);', '    out.push(48); out.push(CR); out.push(LF); out.push(CR);'),
    ('http1_chunked.rs', 'chunked_size_rejects_sixteenth_digit', 'if self.digits >= MAX_SIZE_DIGITS { return self.reject(); }', 'if self.digits + 1 >= MAX_SIZE_DIGITS { return self.reject(); }'),
    ('http1_chunked.rs', 'chunked_ext_rejects_value_bytes', '        } else if crate::http1_head::value_byte_exec(b) {\n', '        } else if is_hex_byte(b) {\n'),
    ('http1_chunked.rs', 'chunked_complete_ext_forgets_value_bytes', '            Phase::Ext => b == CR || (crate::http1_head::is_value_byte(b) && self.line@.len() < MAX_SIZE_LINE),', '            Phase::Ext => b == CR,'),
    ('http1_chunked.rs', 'chunked_ext_accepts_a_byte_past_the_line_cap', 'if self.line_len >= MAX_SIZE_LINE { return self.reject(); }', 'if self.line_len > MAX_SIZE_LINE { return self.reject(); }'),
    ('http1_chunked.rs', 'chunked_framing_step_need_not_spend_budget', '                && after.framing_budget() < before.framing_budget(),', ','),
    ('http1_chunked.rs', 'chunked_complete_done_anywhere', '                && after.done() && chunked_ok(after.fed(), after.body()) && before.phase() == Phase::LastLf,', '                && after.done() && chunked_ok(after.fed(), after.body()),'),
    ('exchange_driver.rs', 'driver_forwards_unlogged_head_in_strict_mode', '        if !logged && strict { return Err(Fault::Log); }', '        if false && strict { return Err(Fault::Log); }'),
    ('exchange_driver.rs', 'driver_dispatches_without_start_record', '    if !started && strict {\n', '    if false {\n'),
    ('exchange_driver.rs', 'driver_skips_completion', '    d.complete(effects, life)\n}\n\n// ---- what an allowed trace guarantees', '    d.close_without(effects)\n}\n\n// ---- what an allowed trace guarantees'),
    ('exchange_driver.rs', 'driver_hands_unmachined_bytes', '                self.pending = Ghost(bytes@);\n                proof', '                self.pending = Ghost(bytes@.push(0u8));\n                proof'),
    ('exchange_driver.rs', 'driver_spec_allows_forward_without_record', '        Step::Forward(status) => if !p.forwarded && p.upstream_head_written && record_allows_forward(p, status)', '        Step::Forward(status) => if !p.forwarded'),
    ('exchange_driver.rs', 'driver_spec_allows_connect_before_record', '        Step::Connect(ok) => if record_allows_dispatch(p) && !p.connected', '        Step::Connect(ok) => if !p.connected'),
    ('http1_body.rs', 'body_length_never_completes', '                if self.remaining == 0 { self.mode = Mode::Done; }\n', ''),
    ('http1_body.rs', 'body_length_overruns_count', '                if self.remaining < n as u64 { n = self.remaining as usize; }\n', ''),
    ('http1_body.rs', 'body_data_ignores_room', '                let mut n = input.len();\n                if room < n { n = room; }\n', '                let mut n = input.len();\n'),
    ('http1_body.rs', 'body_close_completes_a_short_body', '            _ => { self.mode = Mode::Failed; false }', '            _ => { self.mode = Mode::Done; true }'),
    ('http1_body.rs', 'body_empty_length_waits_for_bytes', '            Framing::Length(n) => if n == 0 { (Mode::Done, 0) } else { (Mode::Length, n) },', '            Framing::Length(n) => (Mode::Length, n),'),
    ('http1_body.rs', 'body_done_means_nothing', '            Mode::Done => delimits(self.framing, self.seen@, self.out@),', '            Mode::Done => true,'),
    ('serve_driver.rs', 'serve_spec_cancels_without_failed_drain', '        Step::Cancel => if p.drained == Some(false) && !p.cancelled', '        Step::Cancel => if !p.cancelled'),
    ('serve_driver.rs', 'serve_spec_closes_log_before_drain', '        Step::CloseLog(ok) => if p.workers_closed && (p.drained == Some(true) || p.cancel_waited) && p.log_closed.is_none() {', '        Step::CloseLog(ok) => if p.workers_closed && p.log_closed.is_none() {'),
    ('serve_driver.rs', 'serve_spec_serves_unchecked_socket', '        Step::Served => if p.pending is Admitted {', '        Step::Served => if p.pending is Admitted || p.pending is Accepted {'),
    ('serve_driver.rs', 'serve_skips_wait_after_cancel', '        let _waited = effects.wait_drained(Window::Cancel);\n        d.record(effects, Ghost(Step::Wait(Window::Cancel, _waited)));\n', ''),
    ('serve_driver.rs', 'serve_leaves_workers_open', '    effects.close_workers();\n    d.record(effects, Ghost(Step::CloseWorkers));\n', ''),
    ('serve_driver.rs', 'serve_admits_after_trigger', '                if t {\n                    effects.discard_connection();\n                    self.record(effects, Ghost(Step::Discarded));\n                    return Some(true);\n                }\n', ''),
    ('json.rs', 'json_accepts_leading_zero', '    if s[j] == ZERO { j = j + 1; } else { j = skip_digits(s, j); }', '    j = skip_digits(s, j);'),
    ('json.rs', 'json_accepts_control_bytes', '        } else if b < 0x20 {\n            proof {', '        } else if b < 0x08 {\n            proof {'),
    ('json.rs', 'json_accepts_lone_low_surrogate', '                } else if 0xDC00 <= u && u <= 0xDFFF {\n                    proof {', '                } else if false {\n                    proof {'),
    ('json.rs', 'json_accepts_trailing_bytes', '    if k != bytes.len() { return None; }\n', ''),
    ('json.rs', 'json_misreads_null', '        if s.len() - i >= 4 && s[i + 1] == LOWER_U && s[i + 2] == 108 && s[i + 3] == 108 {', '        if s.len() - i >= 4 && s[i + 1] == LOWER_U && s[i + 2] == 108 {'),
    ('json.rs', 'json_drops_escape_byte', '                text.push(d);\n                proof {\n                    let esc = s@.subrange(p as int, p + 2);', '                proof {\n                    let esc = s@.subrange(p as int, p + 2);'),
    ('json.rs', 'json_accepts_trailing_comma', '        if s[c] != COMMA {\n            proof {\n                assert forall|j: int, its: Seq<Value>|', '        if false {\n            proof {\n                assert forall|j: int, its: Seq<Value>|'),
    ('json.rs', 'json_spec_admits_control_bytes', 'pub open spec fn plain(b: u8) -> bool { b >= 0x20 && b != QUOTE && b != BSLASH }', 'pub open spec fn plain(b: u8) -> bool { b != QUOTE && b != BSLASH }'),
    ('json.rs', 'json_spec_admits_leading_zero', '    d.len() >= 1 && all_digits(d) && (d[0] != ZERO || d.len() == 1)', '    d.len() >= 1 && all_digits(d)'),
    ('json.rs', 'json_spec_admits_lone_low_surrogate', '        || (esc.len() == 6 && esc[1] == LOWER_U && hex4(esc, 2) && !is_high(unit(esc, 2)) && !is_low(unit(esc, 2)) && dec == utf8(unit(esc, 2)))', '        || (esc.len() == 6 && esc[1] == LOWER_U && hex4(esc, 2) && !is_high(unit(esc, 2)) && dec == utf8(unit(esc, 2)))'),
    ('json.rs', 'json_writes_raw_quote', '        if b >= 0x20 && b != QUOTE && b != BSLASH {\n            out.push(b);', '        if b >= 0x20 && b != BSLASH {\n            out.push(b);'),
    ('json.rs', 'json_writes_raw_control', '        if b >= 0x20 && b != QUOTE && b != BSLASH {\n            out.push(b);', '        if b >= 0x08 && b != QUOTE && b != BSLASH {\n            out.push(b);'),
    ('json.rs', 'json_writes_wrong_control_digit', '            let high = hex_digit_exec(b / 16);', '            let high = hex_digit_exec(b % 16);'),
    ('json.rs', 'json_writes_unchecked_number', '            if !number_ok_exec(lex.as_slice()) { return false; }\n', ''),
    ('json.rs', 'json_writes_no_comma', '        if k > 0 { out.push(COMMA); }\n        let ghost b1 = out@;\n        let slice = items.as_slice();', '        let ghost b1 = out@;\n        let slice = items.as_slice();'),
    ('json.rs', 'json_writes_no_colon', '        out.push(COLON);\n        let ghost b3 = out@;', '        let ghost b3 = out@;'),
    ('utf8.rs', 'utf8_spec_admits_overlong_two_byte', '        else if 0xC2 <= b <= 0xDF { if i + 1 < s.len() && cont(s[i + 1]) { 2 } else { 0 } }', '        else if 0xC0 <= b <= 0xDF { if i + 1 < s.len() && cont(s[i + 1]) { 2 } else { 0 } }'),
    ('utf8.rs', 'utf8_spec_admits_surrogates', '                || (b == 0xED && 0x80 <= s[i + 1] <= 0x9F) || (0xEE <= b && cont(s[i + 1]))', '                || (b == 0xED && cont(s[i + 1])) || (0xEE <= b && cont(s[i + 1]))'),
    ('utf8.rs', 'utf8_sanitize_keeps_bad_byte', '            out.push(0xEF); out.push(0xBF); out.push(0xBD);', '            out.push(bytes[p]);'),
    ('utf8.rs', 'utf8_cap_cuts_inside_char', '        if p >= text.len() || n == 0 || p + n > limit {', '        if p >= text.len() || n == 0 || p > limit {'),
    ('projection.rs', 'projection_content_text_uncapped', '    let user_text = match &request.user_text { Some(t) => capped(t.as_slice(), max_text), None => truncated_text(exchange.upload.as_slice(), max_text) };', '    let user_text = match &request.user_text { Some(t) => text(t.as_slice()), None => truncated_text(exchange.upload.as_slice(), max_text) };'),
    ('projection.rs', 'projection_wrong_message_index', '    push_member(&mut ms, K_MESSAGE_INDEX.as_slice(), number(index as u64));', '    push_member(&mut ms, K_MESSAGE_INDEX.as_slice(), number(0));'),
    ('projection.rs', 'projection_wrong_part_key', '    let part = hex_text(part_key(shared.session, shared.exchange.request, index, 0).as_slice());', '    let part = hex_text(part_key(shared.session, shared.exchange.request, index, 1).as_slice());'),
    ('config_schema.rs', 'config_allows_unknown_key', '        if !key_allowed_exec(schema, m.key.as_slice()) { return None; }\n', ''),
    ('config_schema.rs', 'config_allows_duplicate_key', '            if bytes_eq(earlier.key.as_slice(), m.key.as_slice()) { return None; }', '            if false { return None; }'),
    ('config_schema.rs', 'config_accepts_any_logging', '        else if bytes_eq(logging_text.as_slice(), V_AVAILABILITY.as_slice()) { Logging::Availability }\n        else { return None };', '        else { Logging::Availability };'),
    ('config_schema.rs', 'config_wrong_poll_default', '        None => DEFAULT_POLL_MS,', '        None => 0,'),
    ('config_schema.rs', 'config_skips_shipping_uniqueness', '    if !key_unique(members, K_SHIPPING.as_slice()) { return Err(()); }\n', ''),
    ('config_values.rs', 'values_digest_unchecked_length', '    if text.len() != 64 { return None; }\n', ''),
    ('config_values.rs', 'values_secret_allows_space', '        if b < 33 || b > 126 { return false; }', '        if b < 32 || b > 126 { return false; }'),
    ('config_values.rs', 'values_name_allows_dash', '        if !((48 <= b && b <= 57) || (65 <= b && b <= 90) || (97 <= b && b <= 122) || b == 95) { return false; }', '        if !((48 <= b && b <= 57) || (65 <= b && b <= 90) || (97 <= b && b <= 122) || b == 95 || b == 45) { return false; }'),
    ('calendar.rs', 'calendar_century_leap', 'fn is_leap_exec(y: u64) -> (out: bool) ensures out == is_leap(y as int) { y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) }', 'fn is_leap_exec(y: u64) -> (out: bool) ensures out == is_leap(y as int) { y % 4 == 0 }'),
    ('calendar.rs', 'calendar_april_31', '    if m == 2 { if is_leap_exec(y) { 29 } else { 28 } } else if m == 4 || m == 6 || m == 9 || m == 11 { 30 } else { 31 }', '    if m == 2 { if is_leap_exec(y) { 29 } else { 28 } } else if m == 6 || m == 9 || m == 11 { 30 } else { 31 }'),
    ('calendar.rs', 'calendar_spec_february_always_29', '    if m == 2 { if is_leap(y) { 29 } else { 28 } } else if m == 4 || m == 6 || m == 9 || m == 11 { 30 } else { 31 }', '    if m == 2 { 29 } else if m == 4 || m == 6 || m == 9 || m == 11 { 30 } else { 31 }'),
    ('calendar.rs', 'calendar_year_too_narrow', '    push_padded(&mut out, c.year, 4);', '    push_padded(&mut out, c.year, 3);'),
    ('body_reader.rs', 'reader_skips_cursor_advance', '                        let start = self.pos;\n                        self.pos = self.pos + n;', '                        let start = self.pos;'),
    ('body_reader.rs', 'reader_fills_without_clearing', '            self.buffer.clear();\n            self.pos = 0;', '            self.pos = 0;'),
    ('body_reader.rs', 'reader_head_overfills', '    let max = if room < READ_BYTES { room } else { READ_BYTES };', '    let max = READ_BYTES;'),
    ('body_reader.rs', 'reader_truncation_as_end', '                    return if open_ended { Read::End } else { Read::Truncated };', '                    return Read::End;'),
    ('ipv6.rs', 'ipv6_empty_head_before_v4', '                Some(h) => if v4 && h >= 1 {', '                Some(h) => if v4 {'),
    ('ipv6.rs', 'ipv6_eight_groups_with_double_colon', '            let ok = match (head, rest) { (Some(h), Some(t)) => h + t <= 7, _ => false };', '            let ok = match (head, rest) { (Some(h), Some(t)) => h + t <= 8, _ => false };'),
    ('ipv6.rs', 'ipv6_five_digit_group', '        if q == p || q - p > 4 {', '        if q == p || q - p > 5 {'),
    ('sink.rs', 'sink_resends_from_start', '        let piece = slice_subrange(bytes, offset, bytes.len());', '        let piece = slice_subrange(bytes, 0, bytes.len());'),
    ('sink.rs', 'sink_ignores_accepted_count', '                    sent = sent + piece@.subrange(0, n as int);\n                }\n                offset = offset + n;', '                    sent = sent + piece@.subrange(0, n as int);\n                }\n                offset = offset + 1;'),
    ('sink.rs', 'chunk_writer_forgets_failure', '            Err(e) => { self.failed = true; Err(e) }', '            Err(e) => { Err(e) }'),
    ('sink.rs', 'chunk_writer_sends_unframed', '        let bytes = self.stream.frame(data);\n        let written = write_all(&mut self.sink, &bytes);', '        let bytes = self.stream.frame(data);\n        let written = write_all(&mut self.sink, data);'),
    ('base64url.rs', 'base64_accepts_leftover_bits', '        (Some(v0), Some(v1)) if v1 & 15 == 0 => (v0, v1),', '        (Some(v0), Some(v1)) => (v0, v1),'),
    ('base64url.rs', 'base64_accepts_odd_length', '    } else {\n        None\n    }\n}\n\n} // verus!', '    } else {\n        Some(out)\n    }\n}\n\n} // verus!'),
    ('base64url.rs', 'base64_standard_plus', '    if 65 <= c && c <= 90 { Some(c - 65) } else if 97 <= c && c <= 122 { Some(c - 97 + 26) } else if 48 <= c && c <= 57 { Some(c - 48 + 52) }\n    else if c == 45 { Some(62) }', '    if 65 <= c && c <= 90 { Some(c - 65) } else if 97 <= c && c <= 122 { Some(c - 97 + 26) } else if 48 <= c && c <= 57 { Some(c - 48 + 52) }\n    else if c == 43 { Some(62) }'),
    ('base64url.rs', 'base64_encode_drops_tail', '    if bytes.len() - i == 1 {\n        let b0 = bytes[i];', '    if false {\n        let b0 = bytes[i];'),
    ('config_build.rs', 'build_credential_kind_fixed', "        out.push(Credential { tenant: entry.tenant, kind: entry.kind, name, value });", "        out.push(Credential { tenant: entry.tenant, kind: CredentialKind::ApiKey, name, value });"),
    ('config_build.rs', 'build_credential_tenant_fixed', "        tenants.push(inputs[i].tenant);", "        tenants.push(1);"),
    ('config_build.rs', 'build_skips_secret_length_rule', "        if !secret_ok_exec(raw.as_slice(), MAX_CREDENTIAL_BYTES) { return None; }\n", ""),
    ('config_build.rs', 'build_skips_ipv6_rule', "    if parts.authority.len() > 0 && parts.authority[0] == 91 && !crate::ipv6::literal_ok(parts.host.as_slice()) { return None; }\n", ""),
    ('config_build.rs', 'build_bearer_header_misspelt', "            out.push(122); out.push(97); out.push(116); out.push(105); out.push(111); out.push(110);", "            out.push(122); out.push(97); out.push(116); out.push(105); out.push(111); out.push(109);"),
    ('frame_queue.rs', 'frame_queue_cancel_keeps_reservation', '    { self.reserved = false; }', '    { self.reserved = true; }'),
    ('sha256.rs', 'sha256_round_constant_wrong', '    ensures out == k(t as int),\n{\n    if t == 0 { 0x428a2f98 }', '    ensures out == k(t as int),\n{\n    if t == 0 { 0x428a2f99 }'),
    ('sha256.rs', 'sha256_skips_the_feed_forward', '    Words { a: add_exec(s.a, r.a), b: add_exec(s.b, r.b),', '    Words { a: r.a, b: add_exec(s.b, r.b),'),
    ('sha256.rs', 'sha256_schedule_wrong_tap', '        w.push(add_exec(add_exec(add_exec(s1, w[t - 7]), s0), w[t - 16]));', '        w.push(add_exec(add_exec(add_exec(s1, w[t - 8]), s0), w[t - 16]));'),
    ('sha256.rs', 'sha256_pad_without_one_bit', '        tail.push(0x80);', '        tail.push(0x00);'),
    ('sha256.rs', 'sha256_length_in_bytes', '        push_be64(&mut tail, self.length * 8);', '        push_be64(&mut tail, self.length);'),
    ('sha256.rs', 'sha256_whole_block_not_compressed', '                self.words = compress_exec(self.words, block);\n                self.length = self.length + 64;', '                self.length = self.length + 64;'),
    ('utf8.rs', 'utf8_is_valid_ignores_truncation', '        if n == 0 { return false; }\n        proof { assert(rest.subrange(n as int, rest.len() as int) =~= bytes@.subrange(p + n, bytes@.len() as int)); }', '        if n == 0 { return true; }\n        proof { assert(rest.subrange(n as int, rest.len() as int) =~= bytes@.subrange(p + n, bytes@.len() as int)); }'),
    ('http1_exchange.rs', 'exchange_malformed_answers_401', '        Refusal::Malformed => 400,\n        Refusal::Unauthorized => 401,\n        Refusal::MethodNotAllowed => 405,\n        Refusal::Unavailable => 503,\n    }\n}\npub open spec fn', '        Refusal::Malformed => 401,\n        Refusal::Unauthorized => 401,\n        Refusal::MethodNotAllowed => 405,\n        Refusal::Unavailable => 503,\n    }\n}\npub open spec fn'),
    ('http1_exchange.rs', 'exchange_timeout_answers_502', '    if fault == Fault::Timeout { 504 } else { 502 }', '    502'),
    ('http1_exchange.rs', 'exchange_bodiless_status_streams', 'if self.phase != Phase::Open || status < 200 || status > 599 || status == 204 || status == 304 { return None; }', 'if self.phase != Phase::Open || status < 200 || status > 599 { return None; }'),
    ('http1_exchange.rs', 'exchange_fixed_body_after_204', 'if body.len() > 0 || crate::headers::has(&fields, CONTENT_LENGTH.as_slice())', 'if crate::headers::has(&fields, CONTENT_LENGTH.as_slice())'),
    ('http1_exchange.rs', 'exchange_second_head_allowed', '        if self.phase != Phase::Open || status < 200 || status > 599 { return None; }\n        if status == 204', '        if status < 200 || status > 599 { return None; }\n        if status == 204'),
    ('http1_exchange.rs', 'exchange_interim_repeats', '        if self.phase != Phase::Open || self.interim { return None; }', '        if self.phase != Phase::Open { return None; }'),
    ('http1_exchange.rs', 'exchange_upstream_target_unchecked', '        if path.len() == 0 || path[0] != 47 || !all_vchar(path) { return None; }', '        if path.len() == 0 || !all_vchar(path) { return None; }'),
    ('http1_exchange.rs', 'exchange_101_is_interim', '    if status == 101 { return UpstreamStatus::Refused; }\n', ''),
    ('http1_exchange.rs', 'exchange_stream_starts_ended', '    { ChunkStream { ended: false, out: Ghost(Seq::empty()), body: Ghost(Seq::empty()) } }', '    { ChunkStream { ended: true, out: Ghost(Seq::empty()), body: Ghost(Seq::empty()) } }'),
    ("exchange_lifecycle.rs", "start_record_names_wrong_selector", "    metadata::encode_request_start(time_ms, route.selector, destination.text.as_slice())", "    metadata::encode_request_start(time_ms, route.origin as u64, destination.text.as_slice())"),
    ("exchange_lifecycle.rs", "start_record_names_wrong_destination", "    metadata::encode_request_start(time_ms, route.selector, destination.text.as_slice())", "    metadata::encode_request_start(time_ms, route.selector, destination.authority.as_slice())"),
    ("health.rs", "readiness_ignores_workers", "\n{\n    if !admission_healthy || !workers_healthy { Readiness::AdmissionUnavailable }", "\n{\n    if !admission_healthy { Readiness::AdmissionUnavailable }"),
    ("health.rs", "readiness_fails_availability_mode_on_log", "\n{\n    if !admission_healthy || !workers_healthy { Readiness::AdmissionUnavailable }\n    else if requires_audit && !log_healthy { Readiness::AuditUnavailable }", "\n{\n    if !admission_healthy || !workers_healthy { Readiness::AdmissionUnavailable }\n    else if !log_healthy { Readiness::AuditUnavailable }"),
    ("health.rs", "gap_counts_every_failure", "        if count { self.reported = true; }", ""),
    ("health.rs", "gap_counts_in_strict_mode", "        let count = failed && self.availability && !self.reported;", "        let count = failed && !self.reported;"),
    ("destination.rs", "destination_rejects_long_label", "            if k + 1 - start > MAX_LABEL {", "            if k + 1 - start > MAX_LABEL - 1 {"),
    ("destination.rs", "destination_rejects_high_port", "    if value == 0 || value > 65535 { return None; }", "    if value == 0 || value > 65534 { return None; }"),
    ("destination.rs", "destination_rejects_ten_byte_text", "    if text.len() > MAX_TEXT || text.len() < 9 {", "    if text.len() > MAX_TEXT || text.len() < 10 {"),
    ("destination.rs", "destination_forgets_text", "    let parts = Parts { text: slice_to_vec(text), authority: slice_to_vec(authority), host, port, path };", "    let parts = Parts { text: slice_to_vec(authority), authority: slice_to_vec(authority), host, port, path };"),
    ("destination.rs", "destination_accepts_double_slash_path", "    if (raw.len() >= 2 && raw[1] == 47) || query < raw.len() || authority.len() == 0 {", "    if query < raw.len() || authority.len() == 0 {"),
    ("destination.rs", "destination_accepts_query", "    if (raw.len() >= 2 && raw[1] == 47) || query < raw.len() || authority.len() == 0 {", "    if (raw.len() >= 2 && raw[1] == 47) || authority.len() == 0 {"),
    ("destination.rs", "destination_accepts_control_bytes", "    if !all_printable_bytes(text) { return None; }\n", ""),
    ("destination.rs", "destination_accepts_port_zero", "    if value == 0 || value > 65535 { return None; }", "    if value > 65535 { return None; }"),
    ("destination.rs", "destination_accepts_http_scheme", "    if !eq(slice_subrange(text, 0, 8), HTTPS.as_slice()) {", "    if false {"),
    ("destination.rs", "destination_accepts_hyphen_after_dot", "            if k + 1 < s.len() && s[k + 1] == 45 { return false; }\n", ""),
    ("destination.rs", "destination_accepts_long_label", "            if k + 1 - start > MAX_LABEL {", "            if k + 1 - start > MAX_LABEL + 1 {"),
    ("destination.rs", "destination_host_keeps_brackets", "        (slice_to_vec(inner), close + 1)", "        (slice_to_vec(slice_subrange(authority, 0, close + 1)), close + 1)"),
    ("inbound.rs", "selector_accepts_leading_zero", "    if digits[0] == 48 && digits.len() > 1 {\n        proof { lemma_leading_zero(path@, digits@); }\n        return None;\n    }\n", ""),
    ("inbound.rs", "selector_accepts_path_suffix", "        if b < 48 || b > 57 {\n            proof { lemma_non_digit(path@, digits@, i as int); }\n            return None;\n        }", "        if b < 48 || b > 57 {\n            proof { lemma_non_digit(path@, digits@, i as int); }\n            break;\n        }"),
    ("inbound.rs", "selector_wraps_on_overflow", "        if acc > (u64::MAX - d) / 10 {\n            proof { lemma_overflow(path@, digits@, i as int, acc, d); }\n            return None;\n        }\n        proof { assert(acc * 10 <= u64::MAX - d) by (nonlinear_arith) requires acc <= (u64::MAX - d) / 10; }\n        acc = acc * 10 + d;", "        acc = acc.wrapping_mul(10).wrapping_add(d);"),
    ("inbound.rs", "bearer_accepts_two_authorization_fields", "if count(fields, AUTHORIZATION.as_slice()) != 1 { return None; }", "if count(fields, AUTHORIZATION.as_slice()) == 0 { return None; }"),
    ("inbound.rs", "bearer_accepts_any_scheme", "if !eq(scheme.as_slice(), BEARER.as_slice()) || value[6] != 32 { return None; }", "if value[6] != 32 { return None; }"),
    ("inbound.rs", "bearer_accepts_oversized_token", "if value.len() < 8 || value.len() - 7 > MAX_TOKEN { return None; }", "if value.len() < 8 { return None; }"),
    ("headers.rs", "headers_forward_client_authorization", "        eq(name, CONTENT_TYPE.as_slice()) || eq(name, ACCEPT.as_slice()) || eq(name, ANTHROPIC_VERSION.as_slice())\n            || eq(name, ANTHROPIC_BETA.as_slice()) || eq(name, OPENAI_BETA.as_slice())", "        eq(name, CONTENT_TYPE.as_slice()) || eq(name, ACCEPT.as_slice()) || eq(name, ANTHROPIC_VERSION.as_slice())\n            || eq(name, ANTHROPIC_BETA.as_slice()) || eq(name, OPENAI_BETA.as_slice()) || eq(name, AUTHORIZATION.as_slice())"),
    ("headers.rs", "headers_keep_nominated_field", "if allowed_name(request, field.name.as_slice()) && !listed(hop, field.name.as_slice()) {", "if allowed_name(request, field.name.as_slice()) {"),
    ("headers.rs", "headers_omit_credential", "    head.push(Field { name: slice_to_vec(credential_name), value: slice_to_vec(credential), sensitive: true });\n", ""),
    ("headers.rs", "headers_leak_credential_sensitivity", "    head.push(Field { name: slice_to_vec(credential_name), value: slice_to_vec(credential), sensitive: true });", "    head.push(Field { name: slice_to_vec(credential_name), value: slice_to_vec(credential), sensitive: false });"),
    ("headers.rs", "headers_forward_encoded_upload", "if has(fields, CONTENT_ENCODING.as_slice()) || has(fields, UPGRADE.as_slice()) || has(fields, TRAILER.as_slice()) {", "if has(fields, UPGRADE.as_slice()) || has(fields, TRAILER.as_slice()) {"),
    ("headers.rs", "headers_ignore_byte_limit", "if !fits(fields) { return Err(Rejection::TooLarge); }\n    let hop = match nominations(fields, true)", "let hop = match nominations(fields, true)"),
    ("headers.rs", "headers_forward_renominated_encoding", "if listed(&hop, CONTENT_ENCODING.as_slice()) { return Err(Rejection::BadRequest); }\n", ""),
    ("headers.rs", "headers_nominations_skip_listed_check", "                let pushed = was_allowed && !was_listed;", "                let pushed = false;"),
    ("headers.rs", "headers_nominations_drop_short_names", "                let pushed = was_allowed && !was_listed;", "                let pushed = was_allowed && !was_listed && name.len() > 7;"),
    ("headers.rs", "headers_complete_spec_vacuous", "    forall|name: Seq<u8>| #[trigger] nominated(fields, name) && allowed(request, name) ==> in_list(hop, name)", "    forall|name: Seq<u8>| #[trigger] nominated(fields, name) && allowed(request, name) && in_list(hop, name) ==> in_list(hop, name)"),
    ("headers.rs", "headers_element_bounds_untrimmed", "        && (s == e || (!is_blank(value[s]) && !is_blank(value[e - 1])))\n", ""),
    ("headers.rs", "headers_fabricate_value", "let copy = Field { name: slice_to_vec(field.name.as_slice()), value: slice_to_vec(field.value.as_slice()), sensitive: field.sensitive };", "let copy = Field { name: slice_to_vec(field.name.as_slice()), value: Vec::new(), sensitive: field.sensitive };"),
    ("body_copy.rs", "body_copy_drops_accepted_count", "self.accepted = self.accepted + (n as u64);", "self.accepted = self.accepted;"),
    ("body_copy.rs", "body_copy_skips_audit_while_log_healthy", "if stream.stream().is_failed() { self.phase = Phase::Audited; return None; }", "if true { self.phase = Phase::Audited; return None; }"),
    ("body_copy.rs", "body_copy_flushes_partial_chunk", "if stream.stream().unsent() == 0 { self.phase = Phase::NeedFlush; } else { self.phase = Phase::Audited; }", "self.phase = Phase::NeedFlush;"),
    ("body_copy.rs", "body_copy_hides_audit_gap", "if n == 0 { self.gap = stream.stream().is_failed(); self.phase = Phase::Done; }", "if n == 0 { self.gap = false; self.phase = Phase::Done; }"),
    ("body_copy.rs", "body_copy_finishes_with_data_pending", "if n == 0 { self.gap = stream.stream().is_failed(); self.phase = Phase::Done; }\n                else { self.phase = Phase::Filled; }", "self.gap = stream.stream().is_failed(); self.phase = Phase::Done;"),
    ("body_copy.rs", "body_copy_writes_unprepared_ticket", "self.ticket = Ghost(write.ticket());", "self.ticket = Ghost(arbitrary());"),
    ("body_copy.rs", "body_copy_strict_log_failure_continues", "if stream.stream().requires_audit() { self.phase = Phase::Failed; self.failure = Some(Failure::Log); }\n                else { self.phase = Phase::Audited; }", "self.phase = Phase::Audited;"),
    ("exchange_lifecycle.rs", "lifecycle_misreports_timeout", "out != metadata::OUTCOME_SUCCESS,\n{\n    match fault {\n        Fault::Connect | Fault::Tls | Fault::Http => metadata::OUTCOME_UPSTREAM_FAILURE,\n        Fault::Timeout => metadata::OUTCOME_UPSTREAM_TIMEOUT,", "out != metadata::OUTCOME_SUCCESS,\n{\n    match fault {\n        Fault::Connect | Fault::Tls | Fault::Http => metadata::OUTCOME_UPSTREAM_FAILURE,\n        Fault::Timeout => metadata::OUTCOME_OTHER,"),
    ("exchange_lifecycle.rs", "lifecycle_records_counts_for_failed_exchange", "let (upload, download) = if self.outcome == metadata::OUTCOME_SUCCESS { (self.upload, self.download) } else { (0, 0) };", "let (upload, download) = (self.upload, self.download);"),
    ("exchange_lifecycle.rs", "lifecycle_drops_download_count", "self.download = copy.accepted_bytes();", "self.download = 0;"),
    ("exchange_lifecycle.rs", "lifecycle_fault_leaves_exchange_open", "        self.outcome = outcome_code(fault);\n        self.state = State::Terminal;", "        self.outcome = outcome_code(fault);"),
    ("shipping_driver.rs", "driver_checkpoints_stale_progress", "            let (resolved, poisoned) = machine.progress();\n            effects.checkpoint(machine, resolved, poisoned);\n            effects.observe(Event::PoisonedUnsent, machine);", "            let (resolved, poisoned) = machine.progress();\n            effects.checkpoint(machine, 0, poisoned);\n            effects.observe(Event::PoisonedUnsent, machine);"),

    ("shipping_wire.rs", "wire_jws_accepts_four_segments", "                (Some(_), Some(_)) => return None,", "                (Some(_), Some(_)) => {}"),
    ("shipping_wire.rs", "wire_jws_accepts_empty_subject", "if subject.len() < 1 || subject.len() > MAX_SUBJECT_BYTES { return None; }", "if subject.len() > MAX_SUBJECT_BYTES { return None; }"),
    ("shipping_wire.rs", "wire_issued_ignores_token_expiry", "let expires_at = if e <= c.expires { e } else { c.expires };", "let expires_at = e;"),
    ("shipping_wire.rs", "wire_revocation_misses_disabled", "let out = eq(code.as_slice(), REVOKED.as_slice()) || eq(code.as_slice(), DISABLED.as_slice());", "let out = eq(code.as_slice(), REVOKED.as_slice());"),
    ("shipping_wire.rs", "wire_retry_after_keeps_trailing_blanks", "    while b > a + 1 && (value[b - 1] == 32 || value[b - 1] == 9)", "    while false"),
    ("shipping_wire.rs", "wire_retry_after_skips_first_field", "        if eq(fields[i].name.as_slice(), RETRY_AFTER.as_slice()) {", "        if eq(fields[i].name.as_slice(), RETRY_AFTER.as_slice()) && i > 0 {"),
    ("shipping_wire.rs", "wire_request_head_drops_batch_id", "            fields.push(field(BATCH_ID.as_slice(), encoded_id, false));", ""),
    ("shipping_wire.rs", "wire_request_head_skips_wire_check", "if !wire_ok(&fields) || !target_ok_exec(target) { return None; }", "if !target_ok_exec(target) { return None; }"),
    ("client_exchange.rs", "client_sends_head_twice", "    let written = write_all(wire, body);\n    let ghost sent = head@ + written.sent@;", "    let written = write_all(wire, head);\n    let ghost sent = head@ + written.sent@;"),
    ("client_exchange.rs", "client_unbounded_interim_heads", "if interim == MAX_INTERIM_HEADS { return Err(ClientFault::Refused); }", ""),
    ("client_exchange.rs", "client_body_over_cap", "if n > cap - out.len() { return Exchanged { result: Err(ClientFault::TooLarge), sent: Ghost(sent) }; }", ""),
    ("client_exchange.rs", "client_truncated_body_as_reply", "Read::Truncated | Read::Malformed | Read::Failed => return Exchanged { result: Err(ClientFault::Body), sent: Ghost(sent) },", "Read::Truncated | Read::Malformed | Read::Failed => return Exchanged { result: Ok(Reply { head: read.head, body: out }), sent: Ghost(sent) },"),
]


MARKERS = ["postcondition not satisfied", "precondition not satisfied", "requires not satisfied", "assertion failed", "invariant not satisfied", "possible arithmetic underflow/overflow"]
LOG = ["--log", "vir-simple", "--log", "vir-option=no_span+no_type"]


def command(source, modules=(), log_dir=None, lifetime=True, mutation=False):
    args = [VERUS, str(source / "lib.rs"), "--crate-type", "lib", "--triggers-mode", "silent"]
    if mutation:
        # One genuine proof failure per function suffices. The outer pool owns
        # parallelism; nested verifier pools only compete for the same CPUs.
        args += ["--multiple-errors", "0", "--no-auto-recommends-check", "--num-threads", "1"]
    for module in modules:
        args += ["--verify-module", module]
    if log_dir:
        args += LOG + ["--log-dir", str(log_dir)]
    if not lifetime:
        args.append("--no-lifetime")
    return args


# --- Verus's simplified VIR, the crate as the verifier sees it -----------------
#
# A batch of mutations is sound to judge from one verifier run only if no
# mutation changed anything another function's proof can see. Verus checks each
# function against the specifications of what it calls, never against their
# bodies, so a mutation confined to the body of an exec or proof function can be
# refuted only inside that function, and cannot change any other function's
# outcome. The VIR log makes that condition checkable: it is diffed against the
# unmutated crate, and the batch is accepted only when the sole differences are
# the bodies of exec/proof functions, one per mutation.

# Crate-wide counters and diagnostic source positions carry no meaning for the comparison.
COUNTERS = re.compile(r"(:id|RustcId)\s+\d+")
DIAGNOSTIC_SPANS = re.compile(r':spans \("[^"]*"\)')
SPAN = re.compile(r"^;; (\S+?):(\d+):\d+: (\d+):\d+")
NAME = re.compile(r":name \((?:Fun :path|Dt Path) (\S+?)\)")
FIELD = re.compile(r'\\.|[()"]|:(?:body|mode|item_kind) ')


def parse_vir(path):
    """Return {key: (kind, spec, body, mode)} and {file: [(start, end, key)]} for a VIR log."""
    items, spans = {}, {}
    span = None
    for chunk in re.split(r"\n(?=[(;])", Path(path).read_text()):
        if chunk.startswith(";;"):
            if match := SPAN.match(chunk):
                span = (Path(match[1]).name, int(match[2]), int(match[3]))
            continue
        if not chunk.startswith("("):
            continue
        kind = chunk[1:].split(None, 1)[0]
        text = " ".join(DIAGNOSTIC_SPANS.sub(":spans (_)", COUNTERS.sub(r"\1 _", chunk)).split())
        body, mode = "", None
        if kind == "Function":
            depth, in_string, fields = 0, False, {}
            for token in FIELD.finditer(text):
                t = token[0]
                if t.startswith("\\"):
                    continue
                if in_string:
                    in_string = t != '"'
                elif t == '"':
                    in_string = True
                elif t == "(":
                    depth += 1
                elif t == ")":
                    depth -= 1
                elif depth == 1:
                    fields[t.strip()] = token.end()
            body_at = fields[":body"]
            body, text = text[body_at:], text[:body_at]
            mode = text[fields[":mode"]:].split(None, 1)[0]
            if "(ItemKind Const)" in text[fields[":item_kind"]:].split(")", 1)[0] + ")":
                mode = "Const"
        name = NAME.search(text)
        key = (kind, name[1]) if name and kind in ("Function", "Datatype") else (kind, text)
        items[key] = (kind, text, body, mode)
        if span and name:
            spans.setdefault(span[0], []).append((span[1], span[2], key))
    for file_spans in spans.values():
        file_spans.sort()
    return items, spans


def item_at(spans, file, line):
    """The item whose source region holds this line: the last one starting at or above it."""
    found = None
    for start, _end, key in spans.get(file, ()):
        if start > line:
            break
        found = key
    return found


def local_changes(baseline, mutated):
    """(exec/proof functions whose bodies alone differ, items that differ in any other way).

    None when the item sets differ, which no body-only change can cause.
    """
    if baseline.keys() != mutated.keys():
        return None
    changed, beyond = set(), set()
    for key, (kind, spec, body, mode) in mutated.items():
        base_kind, base_spec, base_body, _ = baseline[key]
        if kind != base_kind or spec != base_spec or (body != base_body and (kind != "Function" or mode not in ("Exec", "Proof"))):
            beyond.add(key)
        elif body != base_body:
            changed.add(key)
    return changed, beyond


ERROR = re.compile(r"^(error|warning|note)(?:\[\w+\])?: (.*)$", re.M)
LOCATION = re.compile(r"^\s*(?:-->|:::) (\S+?):(\d+):\d+", re.M)


def error_blocks(output):
    """(message, [(file, line)]) for each error Verus reported."""
    headers = list(ERROR.finditer(output))
    blocks = []
    for i, header in enumerate(headers):
        if header[1] != "error":
            continue
        text = output[header.end():headers[i + 1].start() if i + 1 < len(headers) else len(output)]
        locations = [(Path(m[1]).name, int(m[2])) for m in LOCATION.finditer(text)]
        blocks.append((header[2], locations))
    return blocks


# --- Running the mutations ----------------------------------------------------

def apply(workdir, name, mutations):
    """Copy the crate and apply each (filename, before, after)."""
    target = workdir / name / "src"
    shutil.copytree(SOURCE, target)
    clean = True
    for filename, before, after in mutations:
        path = target / filename
        text = path.read_text()
        clean = clean and text.count(before) == 1
        path.write_text(text.replace(before, after))
    return target, clean


def check(workdir, filename, name, before, after):
    """Return a report line, or raise when the mutated crate still verifies.

    The mutated module is checked alone first. A proof failure there is a failure
    of the whole crate too, so only a module that still verifies on its own falls
    back to verifying every module, which catches defects refuted by a caller.
    """
    target, _clean = apply(workdir, name, [(filename, before, after)])
    for modules in ([Path(filename).stem], []):
        result = subprocess.run(command(target, modules, mutation=True), capture_output=True, text=True)
        output = result.stdout + result.stderr
        if result.returncode != 0 and not any(marker in output for marker in MARKERS) and "Resource limit (rlimit) exceeded" in output:
            # Isolate each function from the accumulated solver context. A
            # timeout still never counts as evidence that a defect was rejected.
            result = subprocess.run(command(target, modules, mutation=True) + ["-V", "spinoff-all", "--rlimit", "100"], capture_output=True, text=True)
            output = result.stdout + result.stderr
        if result.returncode != 0:
            if not any(marker in output for marker in MARKERS):
                raise RuntimeError(f"{name}: expected a proof failure, got:\n{output}")
            return f"{name}: rejected by proof" + ("" if modules else " outside its module")
    raise RuntimeError(f"{name}: expected a proof failure, got:\n{output}")


def check_batch(workdir, baseline, index, batch, attempt=0):
    """Verify every mutation of a batch in one run; fall back to single runs for what the batch cannot judge.

    `batch` is [(mutation, expected function key)], one mutation per function.
    """
    name = f"batch{index}" + (f"-{attempt}" if attempt else "")
    target, clean = apply(workdir, name, [(m[0], m[2], m[3]) for m, _ in batch])
    modules = sorted({Path(m[0]).stem for m, _ in batch})
    log_dir = workdir / name / "vir"
    result = subprocess.run(command(target, modules, log_dir, lifetime=False, mutation=True), capture_output=True, text=True)
    output = result.stdout + result.stderr
    expected = {key: m for m, key in batch}
    reason = None
    if not clean:
        reason = "mutations overlap"
    elif not (log_dir / "crate-simple.vir").exists():
        reason = "no VIR log"
    elif (local := local_changes(baseline, (parsed := parse_vir(log_dir / "crate-simple.vir"))[0])) is None:
        reason = "the set of items differs"
    else:
        items, spans = parsed
        changed, beyond = local
        if beyond and beyond <= set(expected) and attempt == 0:
            # Mutations that edited their own function's specification: single runs for
            # those, one more batched run for the rest.
            print(f"{name}: {len(beyond)} mutations change a specification; rerunning the other {len(batch) - len(beyond)} together", flush=True)
            rest = [(m, key) for m, key in batch if key not in beyond]
            return [check(workdir, *expected[key]) for key in sorted(beyond)] + (check_batch(workdir, baseline, index, rest, 1) if rest else [])
        if beyond:
            reason = f"changes reach beyond the mutated functions: {sorted(k[1] for k in beyond)}"
        elif changed != set(expected):
            reason = f"changed bodies do not match the mutated functions: {sorted(k[1] for k in changed ^ set(expected))}"
        else:
            refuted = set()
            for message, locations in error_blocks(output):
                if not locations:
                    continue  # "aborting due to N previous errors"
                owner = item_at(spans, *locations[0])
                if owner in expected and any(marker in message for marker in MARKERS):
                    refuted.add(owner)
            # VIR established that every edit is an independent exec/proof body.
            # An unrelated error (e.g. a solver resource limit) cannot invalidate
            # a genuine proof failure in one of those bodies. Never count that
            # unrelated error as evidence; individually check only missing owners.
            missing = set(expected) - refuted
            if missing:
                print(f"{name}: {len(refuted)} mutations refuted independently; checking the remaining {len(missing)} individually", flush=True)
                return [f"{m[1]}: rejected by proof" if key in refuted else check(workdir, *m)
                        for m, key in batch]
    if reason is None:
        return [f"{m[1]}: rejected by proof" for m, _ in batch]
    if len(batch) == 1:
        return [check(workdir, *batch[0][0])]
    # Isolate structural/specification changes instead of throwing away batching
    # for every independent mutation that happened to share their verifier run.
    print(f"{name}: {reason}; splitting its {len(batch)} mutations", flush=True)
    middle = len(batch) // 2
    return (check_batch(workdir, baseline, f"{index}-{attempt}L", batch[:middle])
            + check_batch(workdir, baseline, f"{index}-{attempt}R", batch[middle:]))


def plan(baseline, baseline_spans):
    """Split the mutations into batches of distinct exec/proof functions, plus the rest for single runs."""
    singles, keyed = [], []
    for mutation in MUTATIONS:
        filename, name, before, _after = mutation
        source = (SOURCE / filename).read_text()
        assert source.count(before) == 1, (name, source.count(before))
        line = source[:source.index(before)].count("\n") + 1
        key = item_at(baseline_spans, filename, line)
        if key is None or key[0] != "Function" or baseline[key][3] not in ("Exec", "Proof"):
            singles.append(mutation)
        else:
            keyed.append((mutation, key))
    # A mutation joins the first batch whose copy of its function is untouched and
    # in whose edited text its `before` is still unique, so earlier edits in the
    # batch cannot hide it or duplicate it.
    batches, texts = [], []
    for mutation, key in keyed:
        filename, _name, before, after = mutation
        for batch, text in zip(batches, texts):
            current = text.setdefault(filename, (SOURCE / filename).read_text())
            if all(k != key for _, k in batch) and current.count(before) == 1:
                batch.append((mutation, key))
                text[filename] = current.replace(before, after)
                break
        else:
            batches.append([(mutation, key)])
            texts.append({filename: (SOURCE / filename).read_text().replace(before, after)})
    return batches, singles


if __name__ == "__main__":
    # Optional focused reruns after changing one proof module; default remains all.
    if selected := os.environ.get("MUTATION_FILTER"):
        MUTATIONS = [m for m in MUTATIONS if selected in m[0] or selected in m[1]]
        if not MUTATIONS:
            raise SystemExit(f"no mutations match {selected!r}")

    with tempfile.TemporaryDirectory(prefix="gateway-mutations-") as temporary:
        workdir = Path(temporary)
        started = time.monotonic()
        print("Verifying production core and recording mutation baseline...", flush=True)
        subprocess.run(command(SOURCE, log_dir=workdir / "baseline"), check=True)
        print(f"Production core verified in {time.monotonic() - started:.1f}s", flush=True)
        baseline, baseline_spans = parse_vir(workdir / "baseline" / "crate-simple.vir")
        batches, singles = plan(baseline, baseline_spans)
        jobs = [lambda i=i, b=b: check_batch(workdir, baseline, i, b) for i, b in enumerate(batches)]
        jobs += [lambda m=m: [check(workdir, *m)] for m in singles]
        # Each job verifies its own copy, so the independent runs share the machine.
        workers = os.cpu_count() or 1
        print(f"Checking {len(MUTATIONS)} mutations in {len(batches)} batches and {len(singles)} single runs with {workers} workers...", flush=True)
        mutations_started = time.monotonic()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(job) for job in jobs]
            failures = []
            for completed, future in enumerate(as_completed(futures), 1):
                try:
                    print("\n".join(future.result()), flush=True)
                except Exception as error:
                    failures.append(str(error))
                    print(str(error), flush=True)
                print(f"Completed {completed}/{len(jobs)} mutation jobs in {time.monotonic() - mutations_started:.1f}s", flush=True)
            if failures:
                raise SystemExit(f"{len(failures)} mutation jobs failed; see diagnostics above")
    print(f"{len(MUTATIONS)} mutations rejected by proof ({len(batches)} batched runs, {len(singles)} single runs)", flush=True)
