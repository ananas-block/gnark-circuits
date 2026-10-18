# Coverage

All checks refer to the revision and file hashes in source.json. The experimental copy removes only the newly added tangent block. No deployed verifying key is in scope.

| Item | Status | Evidence |
|---|---|---|
| Polynomial residual identities | checked | check_identities.py; identities.log |
| Equal-coordinate tangent implication | checked | models.md; coincident tangent identity in identities.log |
| Balanced mu nonzero guard | checked | models.md native bounds; dependencies.md HintBalanced and rank-one guard rows |
| Exact mu+2lambda guard | checked | models.md carry proof; exact inequalities in identities.log; 69 alias cases and forged correction in solver.log |
| Table membership and final anchor | checked | compliance.md; components/ladder.md |
| Arithmetic dependencies | checked | dependencies.md implementation locations; fixtures.log tensor, projection, range and lookup suites |
| Malicious hints with terminal assertion | checked | solver.log: TestResidualTerminalRejectsForgedChord for 1,2,3,63 steps and full signature hint-forgery suite |
| Negative control without terminal assertion | checked | solver.log: steps1/terminalfalse accepts the wrong output; demonstrates the caller precondition |
| Native aliases and boundary witnesses | checked | solver.log: TestSlopeGuardNativeAliases; fixtures.log arithmetic and canonical boundary suites |
| Constraint removal preserves honest proofs | checked | fixtures.log and proof.log; 51,045 constraints |
| Public-input and privacy changes | checked | removal adds no variables or public inputs; statement.md |
| Host/circuit divergence | checked | host slopes are untrusted; altered first slope is exercised; exact identity covers arbitrary slope witnesses, models.md |
| External obligations | checked | obligations.md: commitment verification, matching setup, lazy-step caller contract |
| Open leads and test gaps | checked | findings.md; no unresolved lead remains for the tangent implication question |

## Exit gate

- Every scoped row has evidence above; components/ladder.md has no pending item.
- Dependency operation entries cite implementations in this checkout or gnark v0.16.4, plus executed regressions in fixtures.log.
- Both initial leads are settled in findings.md. The distinction between an unanchored helper and the complete ladder is covered by a control experiment.
- No unrun test gap is carried as a conclusion. Fixture and proof commands exited successfully; the one excluded helper-only test and its replacement integration cases are explained in divergences.md.
- No full-signature exploit is asserted. The result is a verified implication of constraints, with its necessary caller conditions explicit in models.md.
- Verifier/setup dependencies are recorded in obligations.md.
