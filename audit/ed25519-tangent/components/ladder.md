# Ladder checklist

All checked entries refer to the revision/file hashes in ../source.json.

| Item | Status | Evidence |
|---|---|---|
| Every arbitrary slope appears in a constrained relation | checked | quadrupleAddChecked tangent/chord/second-slope equations; ../models.md |
| Coincident chord has a forced tangent in the full ladder | checked | exact K identity and backwards induction; ../identities.log |
| Zero denominators do not free coordinates | checked | nonsingularity argument in ../models.md; discriminant recomputed |
| Native zero predicate cannot be forged | checked | gnark IsZero two constraints; ../dependencies.md |
| Nonzero guards test modulo p, not only native q | checked | signed bounds plus exact carry lift; 69 alias cases in ../solver.log |
| Checked membership reaches every table row | checked | curve maps, distinct-x additions, committed full rows; ../compliance.md |
| Terminal membership anchors every earlier step | checked | final assertMontOnCurve plus polynomial identities; 1,2,3,63-step solver regressions |
| Hints remain untrusted | checked | forged slope accepted by unanchored control; rejected by all anchored cases, and full signature forged-hint suite |
| Honest witnesses and edge values remain solvable | checked | ../fixtures.log: Ed25519 corpus, scalar/torsion edges and internal arithmetic tests; ../proof.log: complete SHA-512 signature proof verifies |
| Extra public information or state changes | n.a. | only an internal constraint block is removed |
