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
            markers = ["postcondition not satisfied", "assertion failed", "invariant not satisfied"]
            if result.returncode == 0 or not any(marker in output for marker in markers):
                raise RuntimeError(f"{name}: expected a proof failure, got:\n{output}")
            print(f"{name}: rejected by proof", flush=True)
        finally:
            (target / filename).write_text(original)
