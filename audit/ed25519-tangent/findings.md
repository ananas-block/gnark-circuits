# Findings and checked conclusions

## Checked: the added tangent block is redundant in this checkout

- Component: `ed25519/short.go`, quadrupleAddChecked and shortVerify.
- What was checked: whether the additional coincident-chord tangent constraint excludes a witness that the previous exact slope guards and terminal curve check would accept in the complete ladder.
- Method: exact symbolic residual identities, signed-limb/native-carry bound proof, dependency constraint trace, a tangent-removal mutation of the actual implementation, adversarial solver cases and a complete Groth16 proof.
- Evidence: models.md, identities.log, solver.log, fixtures.log, proof.log; source hashes in source.json.
- Result: with checked table rows, both exact slope guards and final membership, backward induction forces K=0 at every step. At coincident coordinates K=0 is exactly the added tangent equation. Removing only that block preserves the signature predicate and reduces constraints from 58,232 to 51,045.

## Checked: the standalone wrong-output regression omits a necessary caller precondition

- Component: `ed25519/ladder_exception_audit_test.go`, TestCoincidentWrongOutputRejected.
- What was checked: whether its acceptance after removing the tangent block demonstrates acceptance by the complete ladder.
- Method: paired solver circuits using the actual step, with and without terminal membership; multi-step propagation tests.
- Evidence: fixtures/residual_guard_test.go.txt and solver.log, including 1,2,3,63-step anchored variants.
- Result: the unanchored helper accepts a forged zero chord slope. Every anchored variant rejects by an actual constraint. The helper-only acceptance is not a signature forgery.

## Checked: the upstream design removed the previous guards

- Component: other checkout's prover/server/circuits/ed25519/short.go, quadrupleAddChecked and shortVerify.
- What was checked: whether both checkouts combine the same set of guards.
- Method: source comparison.
- Evidence: divergences.md.
- Result: the upstream tangent check replaces a guard strategy that this checkout retained. Porting the tangent block on top of those existing guards duplicated the protection.

## Leads

Both initial leads are resolved by the checked entries above. No open lead remains for this implication review.

## Test gaps

No unrun gap remains for the scoped implication. The symbolic proof covers arbitrary slope witnesses; finite solver samples are confirmation of the code mapping, not an exhaustive security argument by themselves.
