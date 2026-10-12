#!/usr/bin/env python3
"""Check that critical-constraint removals break the negative tests in a copy."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile


source = Path(__file__).resolve().parents[2]
cases = [
    (
        "nonzero_u",
        "ed25519/short.go",
        "\tc.api.AssertIsDifferent(c.api.Add(0, 0, u.Limbs()...), 0)",
        "",
        "^TestRejectsZeroReconstruction$",
        "zero reconstruction forged an invalid signature",
        "./ed25519",
    ),
    (
        "canonical_s",
        "ed25519/verify.go",
        "\tc.fr.AssertCanonical(s)",
        "",
        "^TestRejectsBadSignaturesAndHints/S_plus_L$",
        "invalid signature accepted",
        "./ed25519",
    ),
    (
        "terminal_curve",
        "ed25519/soundness_test.go",
        "\tc.assertMontOnCurve(c.montReduce(r))",
        "\t_ = r // remove the terminal assertion while keeping the circuit compilable",
        "^TestFinalCurveRejectsFreeCoincidentChord$",
        "free coincident chord slope accepted",
        "./ed25519",
    ),
    (
        "projected_quotient_bound",
        "p256/emfield/plain.go",
        "\tf.rc.Check(api.Add(kExpr, offset), kBits)",
        "",
        "^TestEdProjectedReducerRejectsAliases$",
        "forged remainder 49585460914597928490167773134620907114776225952486478849090524382754839657096 accepted",
        "./p256/emfield",
    ),
]
results = []
with tempfile.TemporaryDirectory(prefix="ed25519-mutations-") as directory:
    snapshot = Path(directory) / "gnark-gadgets"
    shutil.copytree(source, snapshot, ignore=shutil.ignore_patterns("audit", "testdata", "BENCHMARKS.md"))
    for name, filename, before, after, test, expected, package in cases:
        path = snapshot / filename
        original = path.read_text()
        if original.count(before) != 1:
            raise RuntimeError(f"{name}: mutation target changed")
        try:
            path.write_text(original.replace(before, after))
            run = subprocess.run(
                ["go", "test", package, "-run", test, "-count=1"],
                cwd=snapshot, text=True, capture_output=True, check=False,
            )
        finally:
            path.write_text(original)
        output = run.stdout + run.stderr
        detected = run.returncode != 0 and expected in output
        results.append({"mutation": name, "test": test, "detected": detected, "output": output})
        if not detected:
            raise RuntimeError(f"{name}: mutation was not detected by its assertion\n{output}")
        print(f"{name}: detected")
(source / "audit/ed25519/mutations.json").write_text(json.dumps(results, indent=2) + "\n")
