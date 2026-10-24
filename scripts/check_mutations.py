"""Verify the actual library, then require each deliberate defect to fail its proof.

VERUS=/path/to/verus python3 scripts/check_mutations.py
Normal executable scenarios are tested separately with cargo test --workspace.
"""
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
    ("resource.rs", "mapping_reserve_live_slot", "slots[index] == 0, owner != 0,", "owner != 0,"),
    ("resource.rs", "mapping_wrong_stream_owner", "slots[index] != 0, stream.valid(), stream.owner() == slots[index], stream.capacity() <= capacity,", "slots[index] != 0, stream.valid(), stream.capacity() <= capacity,"),
    ("resource.rs", "mapping_retains_retired_stream", "ensures streams_bound(slots.update(index, 0), streams.update(index, None), capacity),", "ensures streams_bound(slots.update(index, 0), streams, capacity),"),
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
    ("journal.rs", "mint_receipt_without_commit", "if !self.record_durable_frame(t, &frame)", "if false"),

    ("framing.rs", "omit_sealed_checksum", "append(&mut self.bytes, checksum.as_slice());", ""),
    ("framing.rs", "discard_sealed_record", "RecordFrame { bytes: self.bytes,", "RecordFrame { bytes: Vec::new(),"),
    ("journal.rs", "deny_valid_typed_commit", "let ok = self.record_durable(t, frame.bytes());", "let ok = false;"),

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
    ("journal.rs", "deny_written_record", "if self.failed || t.start != self.written || t.end != self.pending", "if true || t.start != self.written || t.end != self.pending"),
    ("journal.rs", "deny_ready_sync", "if self.failed || self.pending != 0 { return false; }", "if true { return false; }"),
    ("journal.rs", "deny_durable_ack", "if self.failed || t.start != self.acknowledged || t.end <= t.start || self.durable < t.end", "if true"),
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
    ("policy.rs", "unauthenticated_identity", "if digest_equal(self.identities[i].digest.as_slice(), digest) {", "if true {"),
    ("policy.rs", "cross_tenant_route", "if r.tenant == self.tenant && r.selector == selector {", "if r.selector == selector {"),
    ("policy.rs", "expand_root_grants", " || !root_contains(&grants, route)", ""),
    ("policy.rs", "erase_validated_root_snapshot", "grants: Ghost(grants@)", "grants: Ghost(Seq::empty())"),
    ("policy.rs", "erase_validated_credential_snapshot", "credential_tenants: Ghost(credential_tenants@)", "credential_tenants: Ghost(Seq::empty())"),
    ("policy.rs", "cross_tenant_credential", "credential_tenants[route.credential] != route.tenant", "false"),
    ("policy.rs", "unknown_origin", "route.origin >= origin_count", "false"),
    ("policy.rs", "wrong_dispatch_origin", "{ self.policy.routes[self.route].origin }", "{ 0 }") ,
    ("policy.rs", "ambiguous_identity", "|| digest_equal(identities[j].digest.as_slice(), identities[i].digest.as_slice())", ""),
]


def command(source):
    return [VERUS, str(source / "lib.rs"), "--crate-type", "lib", "--triggers-mode", "silent"]


subprocess.run(command(SOURCE), check=True)
with tempfile.TemporaryDirectory(prefix="gateway-mutations-") as temporary:
    target = Path(temporary) / "src"
    shutil.copytree(SOURCE, target)
    for filename, name, before, after in MUTATIONS:
        original = (SOURCE / filename).read_text()
        assert original.count(before) == 1, (name, original.count(before))
        (target / filename).write_text(original.replace(before, after))
        try:
            result = subprocess.run(command(target), capture_output=True, text=True)
            output = result.stdout + result.stderr
            markers = ["postcondition not satisfied", "precondition not satisfied", "assertion failed", "invariant not satisfied"]
            if result.returncode == 0 or not any(marker in output for marker in markers):
                raise RuntimeError(f"{name}: expected a proof failure, got:\n{output}")
            print(f"{name}: rejected by proof", flush=True)
        finally:
            (target / filename).write_text(original)
