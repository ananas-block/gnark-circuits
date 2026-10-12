# P-256 gadget findings

This package is a copy of Zolana's prover package
`prover/server/circuits/verifiable-encryption/p256` (commit `18ac9ffa1`, branch
`jorrit/merge-ecies-aes`), with `bitrange` merged into `emfield`. All numbers are
BN254 R1CS constraints with gnark v0.16.3. "Lookup" means the BSB22-backed
range and row tables (one commitment). "No lookup" means pure R1CS with no
commitment.

This repository keeps only the lookup mode. The no-lookup mode (the `...For`
functions with a `lookups` flag) has been removed; its numbers below are
historical measurements kept for comparison.

| Gadget | Lookup | No lookup | gnark std |
| --- | ---: | ---: | ---: |
| ECDH (`ECDH` / `ECDHFor`) | 20,730 | 112,174 | 125,372 (`sw_emulated.ScalarMul`) |
| Key agreement (`AgreeKey` / `AgreeKeyFor`) | 25,359 | 130,086 | 145,819 (`std.AgreeKey`, on-curve fix) |
| ECDSA verification (`VerifyECDSA` / `VerifyECDSAFor`) | 25,896 | 134,537 | 142,468 (`ecdsa.PublicKey.IsValid`) |

The custom rows include the input-validation and completeness fixes from
`22b2cfe` together with the P-256 optimizations. See
[the input and completeness review](../../docs/p256-review.md). The sweeps
below record the original baseline rather than every updated configuration.

The ECDH and ECDSA std rows come from `cmd/benchmark`, and their I/O is emulated
elements. The gadgets read and write bytes or packed fields. Zolana's earlier
byte-in/byte-out std ECDH measured 127,857, and its IsValid measured about 144,127.
[`BENCHMARKS.md`](../BENCHMARKS.md) has historical proving times. Section 8
records the current key-agreement comparison.

The key-agreement std row is `p256/std` (not part of this repository): the same
byte-in, packed-out contract as `AgreeKey`, built only on gnark's
`sw_emulated`, `std/math/emulated` and `std/rangecheck`, with the checks the
old wrappers lacked (0x04 prefix, 8-bit range checks on the 64 key bytes, X and
Y canonical, input point on the curve with y != 0, scalar non-zero) and the
fake-GLV fix on the result. The fix is two assertions, 513 constraints in
total: `AssertIsOnCurve(R)` and `R.Y + Q.Y != 0`. The second is necessary. A
forged `R` on the curve whose y mirrors `Q.y` passes the ladder through
`AddUnified`'s y-sum-zero shortcut even though it is on the curve; the test
`TestStdAgreeKeyRejectsReportForgery` shows the on-curve assertion alone does
not reject that row and the y-sum assertion does. It costs an honest prover
the scalar s = -1 mod n, as the vendored ladder does. Of the 145,819,
`ScalarMul` is about 125k, `ScalarMulBase` about 15.9k, and the rest is
canonicity, byte checks and the reduce-and-decompose of three coordinates.

## 1. The gnark fake-GLV soundness issue

gnark v0.16.3 has no endomorphism on P-256, so `sw_emulated.Curve.ScalarMul`
uses `scalarMulFakeGLV`. The steps:

1. The prover hints `R = [s]Q`.
2. The prover hints a decomposition `s1 + s*s2 = 0 (mod n)` with
   `|s1|, |s2| < 2^129`.
3. The circuit checks `[s1]Q + [s2]R + [3]R == [3]R` with a joint
   double-and-add.

Nothing asserts that `R` lies on the curve. `AddUnified` also returns the
point at infinity whenever `y1 + y2 = 0`, without comparing x. The forgery
works like this:

- Take `s = r/s_sig = -1`.
- Hint `s1 = s2 = 0x5555...55` with sign 0, which satisfies every
  decomposition constraint.
- Hint `R = (x_R, -PK.y)` with an arbitrary `x_R`. `Q + R` hits the y-sum-zero
  shortcut and becomes `O`. The alternating bits select only `Q + R`, so the
  accumulator stays `O` and the final `+[3]R` check passes.
- The off-curve `R` goes into `[u1]G + R`. Picking `x_R` as a root of a
  quartic makes `x(Q) = r`, so `IsValid` accepts a signature nobody signed.
  ECDH through `ScalarMul` can be forged the same way: the shared x is free.

The std benchmark rows are labelled "unsound" for this reason.

### How the vendored ladder closes it (`ladder.go`, `scalarMulChecked`)

- The sign and low bits are boolean. Lookup mode bounds the other digits
  to `[0,3]` and consumes them only as radix-four chunks; no-lookup mode
  checks every bit. `s1` and `s2` are rebuilt as bounded scalars, and the
  check `s * (±s2) + s1 = 0` runs in the scalar field.
- `s2 != 0` is asserted.
- **The hinted `R` is asserted on the curve** before it is used. The input
  `Q` is checked on the curve and canonical at every point-input entry point.
  Byte entry points constrain the prefix and individual key/scalar bytes.
- There is no y-sum-zero shortcut. The ladder uses incomplete affine formulas,
  and every exceptional case is made unsatisfiable:
  - `assertDistinctX(R, Q)`, `assertDistinctX(R, 3Q)` and
    `assertDistinctX(3R, Q)` assert that a bounded sum of squared limb
    differences is nonzero after canonical-coordinate checks. It is zero
    exactly when the coordinates are equal; `TestDistinctXGuard` and the
    native-modulus collision regressions cover it.
  - Each quadruple-and-add step asserts that its output X differs from its
    table point X (`assertLadderOutputDistinct`). A final accumulator curve
    check before the low-bit corrections then certifies all step slopes,
    including the equal-point tangent case. The separate argument and guard
    mutation tests are documented in [`ladder-soundness.md`](ladder-soundness.md).
    The last table addition remains guarded.
  - The final `-Q` and `-R` corrections are guarded additions.
- The accumulator must equal `[3]R_signed`, and the on-curve `R` is returned.
- `TestUnconstrainedHintInScalarMulFakeGLVReportIsRejected` replays the
  report's two hint overrides on compiled ECDH and AgreeKey. It covers an
  off-curve result, an on-curve point sharing the mirrored y, and the honest
  result with the forged decomposition, and every case fails a constraint.
  `TestECDSARejectsReportForgery` replays the report's forged signature
  vector.
- The ECDSA gadget does the following:
  - Checks that `r, s` are in `[1, n)` and canonical.
  - Hints `s^-1` and checks it in the scalar field.
  - Computes `Q = comb(u1) + ladder(u2, PK)` with `completeAdd`, which
    witnesses an x-equality bit and its inverse.
  - Compares `x(Q) mod n == r` as integers with a hinted wrap bit and a
    boolean carry, so honest signatures with `x(Q) >= n` verify (gnark std
    rejects them).

## 2. Original limb layout sweep (ECDH, lookup mode)

| Layout | ECDH | Notes |
| --- | ---: | --- |
| gnark std emulated (byte I/O) | 127,857 | baseline |
| 4x64 limbs | 59,806 | own field |
| 3x88 limbs, 11-bit pieces | 48,694 | intermediate stage; AgreeKey 53,773 |
| 8x32 Solinas fold, 11-bit pieces | **24,242** | final; AgreeKey 30,437 |

The fold layout works because `2^256 mod p` has balanced 32-bit digits all at
most 16 in absolute value. Any product polynomial therefore folds back into 8
limb positions with small coefficients. The quotient shrinks to one derived
native variable of about 42 bits, and products are evaluated at fixed points
through a residue basis. The other parts of the design:

- Carries are grouped.
- Slope limbs are balanced.
- Ladder table x-coordinates are packed 2 limbs per native and y-coordinates
  3 limbs per native. Wider x packing increased carry costs in experiments.
- Canonicity is a 14-row limbwise comparison.
- The point table is a 16-row multi-column lookup.

The lookup-free mode uses the same fold with 32-bit pieces. The fold applies
only to p; the scalar field n uses the general path.

## 3. Range-piece width sweep (lookup mode)

| Piece bits | ECDH | AgreeKey | ECDSA |
| ---: | ---: | ---: | ---: |
| 8 | 24,653 | 31,530 | 32,272 |
| 9 | 24,372 | 31,152 | 31,856 |
| 10 | 24,626 | 31,344 | 32,044 |
| **11** | **24,242** | **30,437** | **31,013** |
| 12 | 25,208 | 31,347 | 31,955 |
| 13 | 28,948 | 35,031 | 35,607 |
| 14 | 37,103 | 43,192 | 43,768 |
| 15 | 53,237 | 59,265 | 59,841 |
| 16 | 84,092 | 89,673 | 90,135 |

32 = 11 + 11 + 10, so a 32-bit limb takes three queries and the table stays
at 2^11 rows. Above 12 bits, the table dominates. Range checks were about 82%
of the cost of the old gnark-derived ladder.

## 4. Original fixed-base comb window sweep

| w | Generator (lookup) | AgreeKey (lookup) | ECDSA (lookup) | AgreeKey (no lookup) |
| ---: | ---: | ---: | ---: | ---: |
| 3 | 11,136 | 32,251 | 32,827 | 156,990 |
| 4 | 9,515 | 30,806 | 31,382 | 147,339 |
| **5** | **9,048** | **30,437** | **31,013** | 142,495 |
| 6 | 9,391 | 30,856 | 31,433 | 139,569 |
| 7 | 9,692 | 31,207 | 31,783 | 137,692 |
| 8 | 9,988 | 31,543 | 32,119 | **136,174** |
| 9 | 10,908 | 32,487 | 33,063 | 136,003 |

The original lookup mode used w = 5; the current selector folds inverse
point pairs and shares multilinear monomials across columns, making w = 7
cheaper. No-lookup mode uses w = 8 (`combWindowFor`). With
no lookups, w = 9 saves only 171 more constraints but doubles the constant
table. The comb's last addition is the complete `completeAdd`, because the top
window can reach the group order.

## 5. Lazy-coordinate bound conditions (checked at compile time)

`Field.Lazy` returns an unreduced element whose limb bounds are tracked as
intervals and never range-checked. Soundness depends on every native
expression staying below `q/2`, where q is the BN254 scalar field. These
conditions are panics during `frontend.Compile`:

- `Lazy` needs the fold layout. Every product coefficient interval must stay
  below `q/2`, and so must every folded limb.
- In `plainCheck`:
  - Every product coefficient and every folded coefficient must stay below
    `q/2`.
  - Each carry group must lift, and so must the top coefficient.
  - The quotient is range-checked with an offset derived from the term ranges.
- The distinct-x guard, the table points and `AssertCanonical` need reduced
  coordinates.

A lazy check multiplies up to three factors. With 32-bit limbs, three factors
fit under 2^253. With 3x88 limbs, they need 264 bits, so lazy coordinates are
impossible on that layout.

## 6. Why the zk.golf secp256k1 record does not transfer

The zk.golf secp256k1 records are 107,563 constraints for a variable-base
multiplication and 12,995 for fixed-base. Each point operation costs more
than gnark's (about 800 vs about 500 constraints). They win only through the
secp256k1 endomorphism `phi(x, y) = (beta*x, y)`, which halves the scalar
over the same base for free. secp256k1 also has `a = 0`.

P-256 has `a = -3` and no endomorphism. Halving the ladder needs the fake-GLV
hint, which costs an on-curve check, a 129-bit decomposition and the guards
in section 1. Porting the record's arithmetic would make each operation more
expensive and bring no length reduction. The gain here comes from these
choices instead:

- the fold
- 11-bit pieces
- lazy coordinates
- quadruple-and-add with implicit slopes
- a 16-row lookup table

## 7. Exceptional scalars and completeness

The internal short ladder excludes ±1, ±3 and ±1/3. The public wrapper now
canonicalizes the scalar, detects these six classes, and proves the equivalent
relation `[s/2](2Q) = [s]Q`. The adjusted scalars ±1/2, ±3/2 and ±1/6 are
outside the excluded set. Tests compare both coordinates against the host.

Scalar zero modulo n still gives infinity and is rejected by the public
finite-point multiplication interfaces. Scalars >= n are reduced as before.
ECDSA handles u1=0 by selecting the variable product after a safe inactive
comb/addition branch; the six u2 cases now verify as well.

Native-modulus X-coordinate collisions formerly rejected valid additions;
canonical limb comparisons now accept those cases, including the constructed
ECDSA regression. The guarded final curve check replaces the separate half-tangent slope
certificates; its soundness argument is in `ladder-soundness.md`. The incomplete
ladder guards still require a separate universal completeness argument.

## 8. Key-agreement optimization campaign

The starting revision `fdce0f9` compiled lookup `AgreeKey` to 30,437
constraints. The campaign implementation before rebasing compiled to 25,299:
**16.9% fewer**. The requested reduction of at least 30% in both constraints
and proving time remains unmet.

The preceding 25,351-constraint implementation was measured on the same
Mac17,8 arm64 host with `GOMAXPROCS=8`: sequential alternating
runs gave baseline medians of 117.865 and 115.755 ms, and current candidate
medians of 100.723 and 99.675 ms. The pooled medians are116.148 and100.521ms:
**13.5% less proving time**. Other worktrees and GUI work were active, so
these shared-host timings are provisional. Every run excludes compilation,
setup and witness construction, discards three warm-up proofs, times 21 proofs
and verifies every proof outside the timed interval. The preceding 25,659
implementation measured 99.642 ms during the same batch; its difference from
the current implementation is within host noise. Individual percentage
gains are not added.

The combined changes are bounded radix-four scalar digits, two-limb X
packing in the ladder table, inverse-pair folding and shared selection
products in the fixed-base comb, and the guarded final curve check described
in [`ladder-soundness.md`](ladder-soundness.md). Field arithmetic uses balanced
modulus coefficients, shared quotient/carry projections, specialized CRT
squares, scalar extraction from triple products, and square reuse with exact
correlated interval bounds. Rational reconstruction supplies two 128-bit
halves, allowing the first ladder step to reuse existing table points.
Public inputs and outputs remain the same.

The CRT square kernel uses 10 native products instead of 13. Its quartic
factor follows [blst's three quadratic-extension squares](https://github.com/supranational/blst/blob/4f72b303888fd02d402a786eeb3d35ac38263ac2/src/fp12_tower.c#L595-L629), with an exact
compile-time check of every symmetric monomial. The two bilinear projections
use a diagonal-plus-rank-one matrix pencil requiring 9 products; the complete
matrix identity is checked at compile time. All original coefficient,
quotient, carry and integer-lifting checks remain enforced.

Early square reuse and wider X packing increased costs; later square reuse
became beneficial with the new square kernel and exact interval analysis.
A radix-eight ladder added table costs and scalar exceptions. Ordinary and
custom-gate GKR prototypes increased constraints, and ARM field-subtraction
measurements were inconclusive. Those variants are excluded. A seven-limb
37-bit layout failed the existing carry bound check. The complete module
test suite passes, including host comparisons, hostile hints, scalar
exceptions and guard mutation tests. Reproduction commands, raw timings,
source revisions and rejected prototypes are retained in the ignored
`docs/perf-loop/` directory at the repository root.

## 9. Simplification with performance retained

The later simplification reduced production Go from 4,305 to 4,149 lines,
excluding tests, comments and blank lines. The projector uses a direct
matrix identity; quartic weights follow the squaring formula; bound tracking
uses one map. Exact tensor verification and integer bounds remain enforced.
Building linear sums in one operation removes extra compiler compression
rows, reducing lookup AgreeKey from 25,351 to 25,299 constraints. Matched
before/after proving medians were about 103.3 and 102.9 ms, a difference
within shared-host variation. Every benchmark proof verified; the full
module tests and independent source review pass.

## 10. Integration with input and completeness fixes

Rebasing onto `22b2cfe` preserves strict byte parsing, canonical limb
comparisons, exceptional-scalar routing and zero-digest ECDSA handling. The
combined lookup AgreeKey has 25,359 constraints versus 29,910 on that main
revision, a 15.2% reduction. The preceding campaign's timing and line-count
measurements above describe its original revision.

The shared field keeps Ed25519's aligned quadratic CRT products and cached
projection-to-full-product reuse. The same square interface supplies its six
products and P-256's ten products. Compile-time tensor checks, differential
field tests and adversarial remainder tests cover both paths.

Sequential main/candidate/main/candidate key-agreement proof runs at
`GOMAXPROCS=8` measured pooled medians of 160.963 and 127.960 ms, respectively,
about 20.5% less time. Every run used three warmups and 21 timed proofs; all
96 proofs verified outside timing. Other host load remains uncontrolled, so
these figures are provisional and are not compared with earlier timings.
The full module tests and `go vet ./p256/... ./ed25519/...` pass. Ed25519's
full verification count also falls from 50,678 to 50,648.
