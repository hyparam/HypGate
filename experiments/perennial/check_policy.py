"""Check policy_proof.v in a dedicated, writable Perennial checkout.

PERENNIAL_ROOT must point to revision 3e3e0a484d61d0a15b578f5d5887ead84f145d71.
Run inside its OPAM environment after installing the pinned dependencies.
This stages experiment files under new/ and builds only the required proof target.
"""
import os
from pathlib import Path
import shutil
import subprocess

root = Path(os.environ["PERENNIAL_ROOT"]).resolve()
experiment = Path(__file__).resolve().parent
for source, target in [
    ("generated/verified_gateway/experiment.v", "new/code/verified_gateway/experiment.v"),
    ("generatedproof/verified_gateway/experiment.v", "new/generatedproof/verified_gateway/experiment.v"),
    ("policy_proof.v", "new/proof/gateway_policy.v"),
]:
    destination = root / target
    destination.parent.mkdir(parents=True, exist_ok=True)
    original = experiment / source
    if not destination.exists() or destination.read_bytes() != original.read_bytes():
        shutil.copyfile(original, destination)

subprocess.run(
    ["make", "-j4", "TIMED=false", "new/proof/gateway_policy.vo"],
    cwd=root,
    check=True,
)
