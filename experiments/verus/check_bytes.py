"""Run byte-level verification and reject corruption, wrong-owner, and audit bypasses."""
import os
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).with_name("bytes.rs")
text = source.read_text()
verus = os.environ.get("VERUS", "verus")
mutations = {
    "corrupt_byte": ("let byte = self.bytes[self.sent];", "let byte = 0u8;"),
    "wrong_owner": ("if self.closed || id != self.id || self.sent == self.bytes.len()",
                    "if self.closed || self.sent == self.bytes.len()"),
    "before_durable": ("|| (self.strict && self.sent == self.durable)", ""),
}
with tempfile.TemporaryDirectory(prefix="gateway-bytes-") as temporary:
    directory = Path(temporary)
    binary = directory / "bytes"
    subprocess.run([verus, str(source), "--compile", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    for name, (before, after) in mutations.items():
        assert text.count(before) == 1
        mutant = directory / (name + ".rs")
        mutant.write_text(text.replace(before, after))
        result = subprocess.run([verus, str(mutant)], capture_output=True, text=True)
        output = result.stdout + result.stderr
        if result.returncode == 0 or "postcondition not satisfied" not in output:
            raise RuntimeError(f"{name}: expected proof failure, got:\n{output}")
        print(f"{name}: rejected by proof")
