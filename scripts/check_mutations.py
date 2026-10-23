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
