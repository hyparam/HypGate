"""Verify that deleting cancellation's store breaks its Perennial proof.

Uses the same PERENNIAL_ROOT and OPAM environment as check_policy.py.
The pinned `goose` and a compatible `go` must be on PATH.
Restores and rechecks the original generated code even on failure.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

here = Path(__file__).resolve().parent
root = Path(os.environ["PERENNIAL_ROOT"]).resolve()
baseline = [sys.executable, str(here / "check_policy.py")]
subprocess.run(baseline, check=True)
with tempfile.TemporaryDirectory(prefix="gateway-go-mutation-") as temporary:
    package = Path(temporary)
    (package / "go.mod").write_bytes((here / "go.mod").read_bytes())
    source = (here / "core.go").read_text()
    original = "func (s *Stream) Cancel() { s.Closed = true }"
    assert source.count(original) == 1
    (package / "core.go").write_text(source.replace(original, "func (s *Stream) Cancel() {}"))
    try:
        subprocess.run([
            "goose", "-dir", str(package), "-out", str(root / "new/code"), "."
        ], check=True)
        result = subprocess.run([
            "make", "-j4", "TIMED=false", "new/proof/gateway_policy.vo"
        ], cwd=root, capture_output=True, text=True)
        output = result.stdout + result.stderr
        if result.returncode == 0 or 'File "./new/proof/gateway_policy.v"' not in output:
            raise RuntimeError("Expected failure in the policy proof:\n" + output)
        print("cancel-without-closing: rejected by Perennial proof", flush=True)
        print(output[-2000:], flush=True)
    finally:
        subprocess.run(baseline, check=True)
