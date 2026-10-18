# Compliance

| Requirement | Code/evidence | Result |
|---|---|---|
| Table points on curve | montFromEd membership; montDouble; montGuardedAdd plus assertDistinctReduced; committed row lookup | follows |
| Exact mu nonzero modulo p | HintBalanced widths and assertPackedDifference; models.md | follows |
| Exact mu+2lambda nonzero modulo p | assertSlopeSumNonzero and checkSlopeGuardBounds; identities.log; 69 alias tests | follows |
| Terminal curve membership | shortVerify calls assertMontOnCurve(final) before edFromMont | follows |
| Residual identities and equal-point implication | check_identities.py; models.md | follows |
| Strict public-key/R policy retained | verify.go unchanged in experimental copy | follows |
