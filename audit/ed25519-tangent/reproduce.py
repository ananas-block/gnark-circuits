"""Reproduce the tangent-removal experiment without editing production files.

Run check_identities.py separately with SymPy 1.14.0 installed.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

report = Path(__file__).resolve().parent
repo = report.parents[1]
root = Path(tempfile.mkdtemp(prefix="gnark-tangent-reproduction-"))
work = root / "circuit"
shutil.copytree(repo, work, ignore=shutil.ignore_patterns(".git", "target", "audit"))
source = work / "ed25519/short.go"
text = source.read_text()
start = text.find("\t// A coincident chord")
if start >= 0:
    end = text.index("\tx2 :=", start)
    text = text[:start] + text[end:]
else:
    raise RuntimeError("expected tangent block not found; review source changes before repeating")
source.write_text(text)
shutil.copyfile(report / "fixtures/residual_guard_test.go.txt", work / "ed25519/residual_guard_test.go")

commands = [
    ["go", "test", "./ed25519", "-run", "Test(Residual|FinalCurveRejects|CoincidentSpecial|SlopeGuardNativeAliases|Verify$)", "-v", "-count=1"],
    ["go", "test", "./ed25519", "./internal/...", "-skip", "^TestCoincidentWrongOutputRejected$", "-count=1"],
    ["go", "run", "./cmd/benchmark", "-only", "Ed25519", "-runs", "1", "-x10=false", "-out", str(root / "proof.md")],
]
for command in commands:
    subprocess.run(command, cwd=work, check=True)
print("Experiment directory:", root)
