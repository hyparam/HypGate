"""Verify the bounded-chunk core, execute scenarios, and reject broken variants.

Usage: VERUS=/path/to/verus python3 experiments/verus/check_stream.py
Uses the Verus release pinned in docs/experiment-results.md.
"""
import os
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).with_name("stream.rs")
text = source.read_text()
verus = os.environ.get("VERUS", "verus")
completion_guard = """if !self.pending || t.owner != self.owner || t.generation != self.generation
            || count > self.offered - self.sent"""
mutations = {
    "replace_unfinished": ("self.sent != self.bytes.len()", "false"),
    "stale_log_ack": (" || chunk != self.chunk", ""),
    "before_durable": (
        "let limit = if self.strict { self.durable } else { self.bytes.len() };",
        "let limit = self.bytes.len();",
    ),
    "wrong_owner": (completion_guard, completion_guard.replace(" || t.owner != self.owner", "")),
    "stale_completion": (completion_guard, completion_guard.replace(" || t.generation != self.generation", "")),
    "pretend_full_write": ("self.sent = self.sent + count;", "self.sent = self.offered;"),
    "wrong_slice": (
        "slice_subrange(self.bytes.as_slice(), self.sent, self.offered)",
        "slice_subrange(self.bytes.as_slice(), 0, self.offered)",
    ),
    "ignore_cancellation": (
        "if self.closed || self.pending || max == 0 || self.generation == u64::MAX",
        "if self.pending || max == 0 || self.generation == u64::MAX",
    ),
}
with tempfile.TemporaryDirectory(prefix="gateway-stream-") as temporary:
    directory = Path(temporary)
    (directory / "admission.rs").write_text(source.with_name("admission.rs").read_text())
    binary = directory / "stream"
    subprocess.run([verus, str(source), "--compile", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    for name, (before, after) in mutations.items():
        assert text.count(before) == 1, name
        mutant = directory / (name + ".rs")
        mutant.write_text(text.replace(before, after))
        result = subprocess.run([verus, str(mutant)], capture_output=True, text=True)
        output = result.stdout + result.stderr
        if result.returncode == 0 or not any(marker in output for marker in ["postcondition not satisfied", "assertion failed"]):
            raise RuntimeError(f"{name}: expected proof failure, got:\n{output}")
        print(f"{name}: rejected by proof")
