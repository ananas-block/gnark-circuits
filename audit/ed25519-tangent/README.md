# Ed25519 tangent-check review

The added coincident-chord tangent block is redundant **when this checkout retains its two exact slope guards, on-curve table rows and final curve assertion**. The other checkout removed those old guards, so this conclusion does not apply to deleting its tangent check.

The exact residual proof is in [models.md](models.md). [check_identities.py](check_identities.py) verifies six polynomial identities and the native-field lift bounds with SymPy 1.14.0. The source revision and hashes are in [source.json](source.json).

The experiment removes only the tangent block in a temporary copy. The old guards reject forged outputs in 1, 2, 3 and 63-step ladders; an unanchored control accepts the same forgery. The Ed25519 fixtures, internal arithmetic suites and a complete SHA-512 signature proof pass. See [solver.log](solver.log), [fixtures.log](fixtures.log), [proof.log](proof.log) and [coverage.md](coverage.md). The standalone wrong-output test omitted from the fixture command lacks the final-curve precondition; [divergences.md](divergences.md) explains this distinction.

| Version | Constraints, 32-byte message |
|---|---:|
| Before the strict-check port | 50,648 |
| Port with both guard strategies | 58,232 |
| Strict policy and conversion checks, existing ladder guards | 51,045 |

Removing the duplicate block saves 7,187 constraints. The remaining strict-check overhead is 397 constraints (0.78%). No proving-time conclusion is drawn from the single proof-validation run in this review.

Reproduce from the repository root:

```sh
python audit/ed25519-tangent/check_identities.py  # requires sympy==1.14.0
python audit/ed25519-tangent/reproduce.py
```

This review creates audit artifacts only; production removal was tested in an isolated copy.
