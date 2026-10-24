"""Verify the actual library, then require each deliberate defect to fail its proof.

VERUS=/path/to/verus python3 scripts/check_mutations.py
Normal executable scenarios are tested separately with cargo test --workspace.
"""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/gateway-core/src"
VERUS = os.environ.get("VERUS", "verus")
GUARD = """if !self.pending || t.owner != self.owner || t.generation != self.generation
            || count > self.offered - self.sent"""
MUTATIONS = [
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
    ("output_frame.rs", "output_frame_corrupts_payload", "copy.push(bytes[i]);", "copy.push(0);"),
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
    ("owned_stream.rs", "provenance_reuses_prior_chunk", "if out.is_some() { self.audit_session = None; self.audit = Ghost(None); }", ""),
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
    ("journal_binding.rs", "binding_accepts_foreign_receipt", "Some(session) => session == receipt.session_id(),", "Some(session) => true,"),
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
    ("buffer_accounting.rs", "omit_in_progress_encoding", "self.bytes() + encoding.len()\n", "self.bytes()\n"),
    ("buffer_accounting.rs", "unreserved_encoding_in_combined_bound", "!queue.reserved() ==> encoding.len() == 0,", "true,"),
    ("frame_queue.rs", "queue_reservation_not_charged", "self.reserved = true;", "self.reserved = false;"),
    ("frame_queue.rs", "queue_push_steals_reserved_slot", "if self.reserved { return Err(item); }", "if false { return Err(item); }"),
    ("frame_queue.rs", "queue_finish_leaks_reservation", "self.reserved = false;", "self.reserved = true;"),
    ("frame_queue.rs", "queue_allows_oversize_encoding_bound", "requires self.valid(), encoding_bytes <= self.payload_limit() + 65,", "requires self.valid(), encoding_bytes <= self.payload_limit() + 66,"),
    ("frame_queue.rs", "frame_queue_ignores_payload_limit", "if item.0.bytes().len() > self.payload_limit + 65 { return Err(item); }", "if false { return Err(item); }"),
    ("frame_queue.rs", "frame_queue_snapshot_omits_records", "self.items().map(|i: int, item: (RecordFrame, T)| item.0)", "Seq::empty()"),
    ("frame_queue.rs", "frame_queue_understates_overhead", "frame_bytes(self.frames())) <= self.capacity() * (self.payload_limit() + 65),", "frame_bytes(self.frames())) <= self.capacity() * (self.payload_limit() + 64),"),
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
    ("buffer_accounting.rs", "underbudget_output_cleanup", "+ (connections + 2 * requests) * 16384 + (queue + requests + 1) * (chunk + 65)", "+ (connections + requests) * 16384 + (queue + requests + 1) * (chunk + 65)"),
    ("buffer_accounting.rs", "underbudget_receipts", "+ (connections + 2 * requests) * 16384 + (queue + requests + 1) * (chunk + 65)", "+ (connections + 2 * requests) * 16384 + (queue + 1) * (chunk + 65)"),
    ("journal.rs", "receipt_frame_overhead_too_small", "ensures self.record().len() == self.payload_len() + 65,", "ensures self.record().len() == self.payload_len() + 64,"),
    ("owned_stream.rs", "owned_retirement_skips_release", "let ok = registry.release_stream(&self.key, self.stream);", "let ok = true;"),
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
    ("framing.rs", "receipt_ignores_header", "let header_ok = equal_bytes(slice_subrange(bytes, 0, 33), header.as_slice());", "let header_ok = true;"),
    ("stream.rs", "acknowledge_unmatched_receipt", "if !receipt.matches_record(header, bytes)", "if false"),
    ("journal.rs", "mint_receipt_without_commit", "if !self.record_durable(t, frame.bytes())", "if false"),

    ("framing.rs", "omit_sealed_checksum", "append(&mut self.bytes, checksum.as_slice());", ""),
    ("framing.rs", "discard_sealed_record", "RecordFrame { bytes: self.bytes,", "RecordFrame { bytes: Vec::new(),"),
    ("journal.rs", "deny_valid_typed_commit", "if !self.record_durable(t, frame.bytes()) { return None; }", "if true { return None; }"),

    ("stream.rs", "audit_wrong_authority", " || self.owner != authority.request_id()", ""),
    ("stream.rs", "audit_wrong_tenant", "tenant: authority.tenant_id(),", "tenant: 0,"),
    ("stream.rs", "audit_wrong_chunk", "request: self.owner, chunk: self.chunk, direction", "request: self.owner, chunk: 0, direction"),
    ("stream.rs", "audit_wrong_bytes", "direction }, self.bytes.as_slice()", "direction }, slice_subrange(self.bytes.as_slice(), 0, 0)"),

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
    ("stream.rs", "wrong_log_chunk_id", "ensures out == self.chunk(),\n    { self.chunk }", "ensures out == self.chunk(),\n    { 0 }"),
    ("journal.rs", "deny_valid_append", "if self.failed || self.pending != 0 || length == 0 || length > u64::MAX - self.written", "if true"),
    ("journal.rs", "deny_written_record", "if self.failed || t.session != self.session || t.start != self.written || t.end != self.pending", "if true || t.start != self.written || t.end != self.pending"),
    ("journal.rs", "deny_ready_sync", "if self.failed || self.pending != 0 { return false; }", "if true { return false; }"),
    ("journal.rs", "deny_durable_ack", "if self.failed || t.session != self.session || t.start != self.acknowledged || t.end <= t.start || self.durable < t.end", "if true"),
    ("resource.rs", "ignore_combined_budget", "total <= 134217728", "true"),
    ("resource.rs", "allow_zero_request_budget", "requests == 0 || ", ""),
    ("resource.rs", "hide_active_requests", "(active, self.slots.len())", "(0, self.slots.len())"),
    ("resource.rs", "count_empty_slots", "if self.slots[i] != 0 { active = active + 1; }", "if self.slots[i] == 0 { active = active + 1; }"),
    ("stream.rs", "deny_valid_ack", "if self.closed || self.failed || owner != self.owner || chunk != self.chunk\n            || end < self.durable || end > self.bytes.len() { return false; }", "if true { return false; }"),
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
    ("framing.rs", "unbounded_payload", "if payload > 1048576 || request == 0 || direction > 1", "if request == 0 || direction > 1"),
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
    ("stream.rs", "before_durable", "let limit = if self.strict { self.durable } else { self.bytes.len() };", "let limit = self.bytes.len();"),
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
]


MARKERS = ["postcondition not satisfied", "precondition not satisfied", "error: requires not satisfied", "assertion failed", "invariant not satisfied"]


def command(source, module=None):
    args = [VERUS, str(source / "lib.rs"), "--crate-type", "lib", "--triggers-mode", "silent"]
    return args + (["--verify-module", module] if module else [])


def check(workdir, filename, name, before, after):
    """Return a report line, or raise when the mutated crate still verifies.

    The mutated module is checked alone first. A proof failure there is a failure
    of the whole crate too, so only a module that still verifies on its own falls
    back to verifying every module, which catches defects refuted by a caller.
    """
    original = (SOURCE / filename).read_text()
    assert original.count(before) == 1, (name, original.count(before))
    target = workdir / name / "src"
    shutil.copytree(SOURCE, target)
    (target / filename).write_text(original.replace(before, after))
    for module in (Path(filename).stem, None):
        result = subprocess.run(command(target, module), capture_output=True, text=True)
        output = result.stdout + result.stderr
        if result.returncode != 0:
            if not any(marker in output for marker in MARKERS):
                raise RuntimeError(f"{name}: expected a proof failure, got:\n{output}")
            return f"{name}: rejected by proof" + ("" if module else " outside its module")
    raise RuntimeError(f"{name}: expected a proof failure, got:\n{output}")


# Optional focused reruns after changing one proof module; default remains all.
if selected := os.environ.get("MUTATION_FILTER"):
    MUTATIONS = [m for m in MUTATIONS if selected in m[0] or selected in m[1]]
    if not MUTATIONS:
        raise SystemExit(f"no mutations match {selected!r}")

subprocess.run(command(SOURCE), check=True)
with tempfile.TemporaryDirectory(prefix="gateway-mutations-") as temporary:
    # Each mutation verifies in its own copy, so the independent runs share the machine.
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as pool:
        for report in pool.map(lambda m: check(Path(temporary), *m), MUTATIONS):
            print(report, flush=True)
print(f"{len(MUTATIONS)} mutations rejected by proof", flush=True)
