# Ground truth

- Local specification: `internal/shortw/ladder-soundness.md`, the residual argument for lazy affine `4P+T`. Its caller contract requires on-curve table points, exact nonzero output guards and an on-curve terminal accumulator.
- Implemented group law: short Weierstrass `y²=x³+a*x+b`, with ordinary chord addition and tangent doubling. Primary reference: [Explicit-Formulas Database](https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html), affine addition and doubling formulas.
- Parameters: `p=2^255-19`, shifted Montgomery coefficient `a=1-486662*(486662/3)`, `b=2*(486662/3)^3-(486662/3)`, all modulo p. `check_identities.py` recomputes the coefficients and checks the discriminant is nonzero.
- Claim under review: the new tangent constraint is logically implied by the existing complete ladder. This claim does not require a standardized Ed25519 acceptance policy; the stricter canonical prime-subgroup policy remains enabled in the experiment.
- No implemented paper is needed for the residual proof: the exact polynomial identities are reproduced by `check_identities.py`, without random sampling or division by witness-dependent quantities.
