"""Check resource-admission proofs and reject ID reuse, eviction, and stale release."""
import os
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).with_name("admission.rs")
text = source.read_text()
verus = os.environ.get("VERUS", "verus")
mutations = {
    "evict_live_request": ("if self.slots[i] == 0 {", "if true {"),
    "reuse_id": ("self.next = self.next + 1;", "self.next = self.next;"),
    "change_budget": ("let id = self.next;", "let id = self.next; self.per_request = 0;"),
    "stale_release": (
        """if key.slot >= self.slots.len() || key.id == 0 || self.slots[key.slot] != key.id {
            return false;
        }""",
        """if key.slot >= self.slots.len() || key.id == 0 {
            return false;
        }""",
    ),
}
subprocess.run([verus, str(source), "--crate-type", "lib"], check=True)
with tempfile.TemporaryDirectory(prefix="gateway-admission-") as temporary:
    for name, (before, after) in mutations.items():
        assert text.count(before) == 1, name
        mutant = Path(temporary) / (name + ".rs")
        mutant.write_text(text.replace(before, after))
        result = subprocess.run([verus, str(mutant), "--crate-type", "lib"], capture_output=True, text=True)
        output = result.stdout + result.stderr
        if result.returncode == 0 or "postcondition not satisfied" not in output:
            raise RuntimeError(f"{name}: expected proof failure, got:\n{output}")
        print(f"{name}: rejected by proof")
