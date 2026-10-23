"""Verify, compile, execute, and check that three broken variants are rejected.

Usage: VERUS=/path/to/verus python3 experiments/verus/check.py
Use the release and Rust toolchain documented in docs/experiment-results.md.
"""
import os
from pathlib import Path
import subprocess
import tempfile

verus = os.environ.get("VERUS", "verus")
source = Path(__file__).with_name("core.rs")
text = source.read_text()
mutations = {
    "send_before_log": (
        "if self.strict && count > self.durable - self.sent { return false; }", ""
    ),
    "overfill": (
        "|| count > self.capacity - (self.received - self.sent)", ""
    ),
    "fail_open_strict": ("if self.strict { self.closed = true; }", ""),
}
with tempfile.TemporaryDirectory(prefix="gateway-proof-") as temporary:
    directory = Path(temporary)
    binary = directory / "core"
    subprocess.run([verus, str(source), "--compile", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    for name, (before, after) in mutations.items():
        assert text.count(before) == 1, name
        mutant = directory / (name + ".rs")
        mutant.write_text(text.replace(before, after))
        result = subprocess.run([verus, str(mutant)], capture_output=True, text=True)
        output = result.stdout + result.stderr
        if result.returncode == 0 or "postcondition not satisfied" not in output:
            raise RuntimeError(f"{name}: expected a proof failure, got:\n{output}")
        print(f"{name}: rejected by proof")
