# Dependency operations checked

Revision and file hashes are pinned in source.json. The gnark module is v0.16.4; gnark-crypto is v0.21.1-0.20260913224755-1409fe592052. Paths below refer to this checkout or the corresponding pinned module-cache source, not just call sites.

| Operation | Implementation evidence | Check |
|---|---|---|
| Balanced hinted slopes | internal/emfield/plain.go:790, layout.go:184 | Every returned limb comes from range-checked pieces minus its signed offset. Raw hint outputs are suggestions; slope equations constrain the resulting value. Exact intervals and maximum recomposition verified in check_identities.py. |
| Bounds metadata | internal/emfield/field.go:126 | WithBounds supplies metadata only; each guarded slope obtains those bounds from HintBalanced's checked pieces. No adversarial limb obtains an unchecked interval in these call sites. |
| Lazy polynomial arithmetic | internal/emfield/plain.go:738; lazy_bounds.go:5 | Folded polynomial products preserve residue modulo p. Expanded interval intersections use equal polynomial expressions; limb/coefficient lift bounds are checked before use. TestLazyBoundExpansionPreservesPolynomial and TestLazySquareBoundsAndCancellation run in fixtures.log. |
| Modular zero and reduction | internal/emfield/check.go:95; plain.go:235,445,492 | Bounded quotient plus native equality and bounded low carries enforce the polynomial relation modulo p. Reduction additionally bounds output limbs. Projected/native-modulus alias regression tests run in fixtures.log. |
| CRT/projected products and squares | internal/emfield/crt.go:194; plain.go:675; projected.go:100,209 | Checked factor/recombine path, shared-product keys, and native/low projections. Tensor and frontend differential tests regenerate coefficients: TestEdProjectionTensorDifferential, TestCRTQuadraticSquaresMatchFold, TestCRTSquareFrontendDifferential, TestProjectionPairMatchesFoldedProduct. |
| Range checking | internal/emfield/layout.go:154,184,207 | Partial-width scaling or tagged lookup constrains each piece. Values and multiplicities enter the commitment before challenge; recomposition gives integer bounds below the native modulus. |
| Table membership | internal/lookup/table.go:59 | All row columns, indices, outputs and counts committed; separated challenge powers and inverse equations bind a complete row. Table built before lookup, with no insertion after finalization on this path. TestLookupRejectsForgery exercises altered lookup/count hints. |
| Native rank-one guards | internal/r1c/assert.go:11,28 | Emits exact L*R=O rows; constants normalized onto the constant-one wire. Certificate coefficients are witness variables, never trusted inverses. |
| Native Add/Sub/Mul | gnark/frontend/cs/r1cs/api.go:34,100,199 | Add/Sub merge linear expressions; Mul emits a native multiplication row for two variables or folds a constant. |
| IsZero and Booleanity | gnark/frontend/cs/r1cs/api.go:642 | Both `m=1-a*inverse` and `a*m=0` fix the zero predicate for either branch, independently of the inverse hint. |
| Nonzero, inverse, batch inverse | gnark/frontend/cs/r1cs/api_assertions.go:40; api.go:333,391 | Nonzero delegates to inverse; each inverse output is checked by multiplication equal to one, including batch outputs. |
| Unchecked division in lookup numerator | gnark/frontend/cs/r1cs/api.go:256 | Enforces divisor*result=numerator. Denominator can vanish only at a commitment-challenge pole; challenge binding is a verifier obligation, not a witness-selected free denominator. |
| Deferred commitment | gnark/std/multicommit/nativecommit.go:116,149 | Aggregates all registered variables, commits before callbacks, and derives callback challenges from that commitment. Verifier binding remains in obligations.md. |

No soundness claim is delegated to the host hint implementation: polynomial constraints, range membership and inverse certificates are the evidence. The end-to-end forged-hint suite exercises PlainCheckHint, BalanceHint, coordinate hints, slope hints, scalar hints, lookup outputs and lookup counts.
