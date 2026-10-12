# Models

Checked data flow: encoded A,R,S,M → bounded byte/limb joins and SHA-512 → canonical h,S → on-curve torsion roots → A0,R0 and bounded torsion indices → torsion equation and bounded short coefficients → fixed-base uS and offset joint multiplication → final curve assertion and complete corrections → prime equation.

Hints occur at byte joins, decompression, torsion decomposition, short reconstruction, recoding, offset choice, slopes, alias handling, field certificates and lookup rows/counts. Their semantic outputs are constrained by the consumers in `components/verification.md`. Unused alias values when z=0 and alternate valid offset choices are permitted auxiliary freedom; they cannot change the terminal equation.

SHA-512 uses rotation-specific word families. Exact-width lookups and one-bit
Boolean constraints bind typed slices, then their 64-bit dense and 128-bit
sparse recompositions. Original input bytes are independently bounded; four-bit
adder carries bind generated low words. Intermediate compression states retain
the A/E families, and the last compression converts to byte slices for the digest.

Checked invariants:

1. Bytes and signed limb representations have the exact bounds assumed by integer joins and native-field lifts.
2. A=[8]Wa+Ta and R=[8]Wr+Tr, with on-curve W and selected eight-torsion constants. Thus A0,R0 have order dividing L. Their unconditional Montgomery maps reject identity prime components, precisely excluding small-order A/R.
3. Tr+[h mod8]Ta=I fixes the full-group torsion equation.
4. `0<u<2^127<L`, `|v|<2^127`, `u*h=v mod L`; therefore multiplying the prime equation by u preserves equivalence.
5. Every table point is the constrained sum J+d1R0+d2A0. Exact reduced-coordinate guards bind its secants, including possible p aliases.
6. Every joint step satisfies its tangent/chord certificates. Nonzero mu and mu+2lambda, and one terminal cubic, propagate curve membership backwards; forward prime-subgroup induction then identifies the actual group operations.
7. Constant selection binds the same j in J and alphaJ. Both parity corrections and the offset correction use complete Edwards addition. The reduced uS witness need not be canonical: successful comb recoding fixes its represented integer below 2^253, and group multiplication depends only on its residue modulo L. Honest field hints supply canonical representatives.
8. Fixed-base window magnitudes select the positive half of the exact constant table; the sign changes only Montgomery y, with propagated signed integer bounds. Shared-monomial selectors retain Boolean input requirements. Host projective coordinates affect witness computation only and preserve unreduced scalar multiplication on the full eight-times-prime-order group.

State transitions: n.a.; this library proves a signature predicate and authorizes no application state transition.

The final field implementation may consume only native and low-prefix projections of a folded polynomial, using an exactly verified aligned CRT basis. All existing integer quotient/carry bounds still lift; balanced modulus digits are the same integer p. Complete coefficient consumers share the product cache with projections. Exact lazy interval intersections tighten metadata without changing the computed polynomial.
