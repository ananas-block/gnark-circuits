# Final curve check for the P-256 ladder

This argument applies to `quadrupleAndAddLazy`, its balanced-slope output guard,
and the curve check in `scalarMulLadder` before the conditional low-bit
corrections. The scalar congruence, input/result validation, table point
construction, and final equality are unchanged inside that ladder.

The public `scalarMulChecked` wrapper canonicalizes the scalar and routes the
six excluded nonzero classes through `[s/2](2Q)=[s]Q`. The adjusted scalars
are outside those classes. P-256 has no affine point of order two, so the
constrained doubling is finite. Applying the ladder argument to its selected
point and scalar proves the original multiplication in both branches.

The cached `RationalReconstruct` implementation in gnark-crypto v0.21.0
uses floor Euclidean division and stops at `r1 < h = floor(sqrt(n))`.
Its alternating denominator coefficients satisfy
`r0 |t1| + r1 |t0| = n`, and `r0 >= h` at termination. Thus
`r1 < h` and `|t1| <= n/h`. For the P-256 group order,
`2^128 h > n`, so both reconstructed halves are strictly below `2^128`.
`TestReconstructionHalvesFit128Bits` checks the fixed-order inequality and
the reconstruction contract at boundary and deterministic random inputs.

The 129-bit hint interface remains in place. The lookup circuit bounds the
highest radix-four digit to one bit. Rebuilding the halves uses that exact
bound.
Let `R` be the signed hinted point and `b1,b2` the two top digits. The
original leading update is
`4(Q+R) + (2b1-3)Q + (2b2-3)R = (1+2b1)Q + (1+2b2)R`.
This selects one of the already checked points `Q+R`, `3Q+R`, `Q+3R`, or
`3Q+3R`. Initializing from that point and resuming at bit pair 126/125
preserves the checked joint multiplication.

## Exact field identities

All equations in this section are in the P-256 base field. Write
`F(x,y) = y² − x³ − a x − b`, with `a = −3`. Membership is `F = 0`.
A step receives `A = (xA,yA)` and an on-curve table point `T = (u,v)`.
The tangent hint `α` is constrained by `2 α yA = 3 xA² + a`. Its doubled
coordinates are

```
x = α² − 2 xA
y = α (xA − x) − yA.
```

Direct expansion gives `F(x,y) = F(xA,yA)`. This identity does not assume that
`A` is on the curve or that its y-coordinate is nonzero.

The two further slope hints and the output coordinates satisfy

```
λ (u − x) = v − y
z = λ² − x − u
μ (z − x) = 2 y
w = u + μ (μ + 2λ)
r = (λ + μ) (w − x) − y.
```

The second slope equation written in the code is
`μ(z−x) + 2λ(u−x) − 2v = 0`; the first equation makes it equivalent to the
one above. The code's output y-coordinate has the additional terms
`λ(u−x)−v`, which equal `−y`.

Define

```
K = (z − x) (u − x + λμ) − 3x² − a.
```

Expansion, using the two slope equations, gives both identities

```
F(u,v) − F(x,y) = (u − x) K
F(w,r) − F(x,y) = (w − x) K.
```

These are polynomial identities. They require no division, so they also
hold at `u = x` and at `z = x`. Since `F(u,v)=0`, subtraction gives

```
F(w,r) = (w − u) K.
```

The output guard proves `w − u = μ(μ+2λ) != 0`. Consequently, if the output
is on the curve then `K=0`, the first identity gives `F(x,y)=0`, and the
doubling identity gives `F(xA,yA)=0`.

Apply this argument backwards from the single final accumulator curve check.
Every step's input, doubled point, and output is on the curve, and every step
has `K=0`. The final check is placed before the conditional `−Q` and `−R`
corrections; the backwards argument ends at the ladder output itself.

## Why these equations prove the group operation

P-256 has odd prime order and cofactor one. An affine on-curve point has
nonzero y, because an affine point with y zero has order two. Thus the tangent
constraint fixes `α` uniquely, and `(x,y)=2A`.

If `u != x`, the first slope equation fixes the ordinary chord slope. If
`u = x`, that equation forces `v=y`. The opposite point is impossible because
`y != 0`. In the equal-point case, `K=0` becomes
`2λy = 3x²+a`, exactly the tangent constraint. Therefore the hidden point
`S=(z, λ(x−z)−y)` is `D+T`, where `D=(x,y)`.

The second slope equation and `y != 0` force `z != x`. They fix the slope
from `D` to `S` as `−(λ+μ)`, and the output is `D+S = 2D+T = 4A+T`.
No exceptional denominator admits an arbitrary result.

Each table point is on the curve: the original three X-distinctness guards
make all eight slot additions proper affine additions. In particular,
`3Q = ±3R` would imply `Q = ±R` because multiplication by three is invertible
in the prime-order group, and the Q/R guard excludes it. The last table
addition remains explicitly guarded. Table lookups select a checked row;
no point-validation assertion was removed from the input or hinted result.

The original bounded rational decomposition and nonzero denominator then
turn the same checked joint multiplication equality into `R=[s]Q`.

## Native implementation of the output guard

Both `λ` and `μ` come from `Field.HintBalanced`. With reduced limb widths
`wi` and radix `2^L`, each signed limb is in `[-2^(wi−1), 2^(wi−1)−1]`.
Let

```
M = Σi 2^(wi−1) 2^(Li).
```

The compile-time guard checks `M < p` and `3M < 2p`. Therefore the only
integer representative of zero modulo p for μ is zero, and the only such
representatives for `S=μ+2λ` are `−p, 0, p`.

The circuit asserts that the native-field value of

```
μ S (S² − p²)
```

is nonzero. A μ or S equal to zero modulo p makes this expression exactly
zero as an integer and hence zero in the native field. Native-field wraparound
cannot hide an exceptional case. There is no assumption that this guard's
integer product fits inside the native field.

As with the earlier native distinct-slope guard, extra collisions modulo the
native field can reject an otherwise honest witness. This is a completeness
limitation, not a soundness freedom. The internal ladder's initial guards
exclude `0, ±1, ±3, ±1/3 (mod n)`. The public wrapper handles the six nonzero
classes by the relation above; zero still produces infinity and is rejected.
The equal-point chord hint now computes the correct tangent instead of a
zero-over-zero quotient.

## Counterexamples and tests

`TestFinalCurveCheckNeedsLadderOutputGuard` supplies a P-256 point `A`, sets
`T=D=2A`, and overrides the first chord hint with `λ=2`. Its `D` satisfies
`y=6x−8`, so `μ=−4` satisfies the second slope equation. The output is `−D`
instead of `3D`. It is on the curve. The test accepts this witness only after
mutating away the native output guard, and rejects it with the real circuit.
A final curve check alone is therefore insufficient.

`TestLadderOutputGuardNeedsFinalCurveCheck` uses the same equal-point input
and `λ=3`, producing an off-curve output with a nonzero output guard. Removing
the final curve check admits it; the real circuit rejects it.

`TestLadderStepHandlesEqualPointWithTangent` checks the honest equal-point
case against Go's P-256 scalar multiplication.

`TestLadderOutputGuard` checks zero μ, zero S, and the positive and negative
integer-p aliases after balanced decomposition, against both the compiled
solver and the direct test engine. Existing hostile hints, fake-GLV report
vectors, invalid recipients, tampered public outputs, host agreement vectors,
and documented scalar exceptions remain regression tests.

## Primary sources and transfer limits

- [Ben Lynn, Explicit Addition Formulae](https://crypto.stanford.edu/pbc/notes/elliptic/explicit.html),
  sections Point Doubling and Point Addition, provide the ordinary affine
  group formulas and their equal/opposite-point cases.
- Local `zkgolf-records/secp256k1-scalar-mul-42a0c2fb/Lazy_StepMath.lean`,
  `first_add` and `second_add`, proves the corresponding two-slope formulas
  using a separate unified-slope equation and a second-denominator condition.
  The residual argument above derives that unified equation from the final
  check and output guard instead; it includes P-256's nonzero `a` term.
- Local `circomlib/circuits/montgomery.circom`, `MontgomeryAdd` and
  `MontgomeryDouble`, witnesses slopes and constrains their products with
  denominators. `escalarmulfix.circom` documents caller-side exclusions of
  equal/zero additions. Those caller assumptions do not justify removing
  this ladder's exceptional-case guard.

The Ed25519 final-check idea motivated this experiment. The argument here is
separate and uses the exact short-Weierstrass constraints in this package.
