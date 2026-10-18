# Differences from the other checkout

The other checkout's `prover/server/circuits/ed25519/short.go` uses the explicit coincident-chord tangent check. Its `quadrupleAddChecked` omits both `assertPackedDifference(mu,0)` and `assertSlopeSumNonzero(mu,lambda)`. Its shortVerify also omits the direct final assertMontOnCurve call.

This checkout retained all three old checks and added the tangent block. The residual argument therefore still applies here, and the new block duplicates a relation already implied by the complete ladder. This conclusion must not be transferred to the other checkout after removing its tangent check: its guard structure is different.

The experiment removes only the newly added tangent block, retains strict point policy and conversion checks, and uses the actual remaining production code. The helper-only `TestCoincidentWrongOutputRejected` is excluded from the fixture run because it omits the terminal curve assertion; that omitted precondition is tested explicitly by an accepting unanchored control and rejecting anchored variants.
