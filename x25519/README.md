# X25519

BN254 gnark gadget for X25519 ECDH, including scalar clamping, RFC 7748
peer decoding, and canonical little-endian output. It accepts curve and twist
inputs and noncanonical peer encodings. Like Go's `crypto/ecdh`, it rejects
all-zero shared secrets. It uses BSB22 lookups and includes no hash or KDF.

```go
shared := x25519.ECDH(api, scalarBytes, peerBytes)
// Derive and bind the ephemeral public key as well:
agreement := x25519.AgreeKey(api, scalarBytes, peerBytes)
ephemeralPublicKey := x25519.ScalarMulGenerator(api, scalarBytes)
```

The inputs and output are `[32]frontend.Variable`. All input elements are
constrained to bytes, including discarded clamping and peer high bits. The
caller chooses their visibility and binds the returned secret to its
application. The benchmark keeps scalar and peer private and exposes the
shared secret. Applications normally consume the
secret inside their circuit instead.

`AgreeKey` returns six named fields:
`RecipientLo`, `RecipientHi`, `EphemeralLo`, `EphemeralHi`, `SharedLo`, and
`SharedHi`. They derive the ephemeral public key from the same clamped scalar
used for ECDH. Each pair packs the first 31 encoded bytes as one big-endian
integer and the final byte as the other.
The encoded X25519 coordinates themselves remain little endian.

Recipient fields bind the **original 32 input bytes**. Changing an ignored
high bit or using a noncanonical alias preserves the shared secret but changes
the packed recipient. Ephemeral and shared outputs use canonical X25519
encodings. This preserves exact transcript binding without rejecting inputs
that RFC 7748 accepts. The caller must bind all required returned fields.

The benchmark includes separate raw ECDH and full AgreeKey rows, with lookups for x1 and x10 circuits. AgreeKey includes ephemeral-key derivation that
raw ECDH does not perform.

Ephemeral public-key derivation uses signed constant windows rather than a
second variable-base multiplication. The implementation uses seven-bit
windows with lookups. With `s=k/8`, `H=[4]G`,
and `C=[2^252-1]H`, the window digits `D_i=2*d_i-(2^w-1)` give
`C + sum(D_i*2^i*H) = [2*s]H = [k]G` directly from the scalar bits.
After consuming `m` low bits, the accumulator coefficient is
`2^252-2^m+2*s_low`: it is positive and even below `2*l`, proving it is
nonzero modulo the odd subgroup order. The same bounds exclude equal
x-coordinates in every nonfinal addition. The last addition can be a tangent;
simultaneous chord and tangent-compatible slope equations handle that case.

## Short relation checker

The raw lookup circuit uses **21,221 constraints**. Full X25519 AgreeKey uses
**25,914**. See
[BENCHMARKS.md](BENCHMARKS.md) for matched x1/x10 proof measurements.
The variable-base checker uses seven 37-bit limbs and shared 10-bit range
lookups. Fixed-base public-key derivation uses six 43-bit limbs with the same
range table.

The circuit computes `Q=[8]P` with three checked affine x-coordinate doublings,
then checks multiplication by `s=k/8`. A constrained Boolean selects the curve
or quadratic twist. The Montgomery equation `B*v²=u³+A*u²+u`, with `B=1` or
`2` and `A=486662`, maps to short Weierstrass coordinates:

```
X = B*(u+A/3), Y = B²*v
Y² = X³ + a*X + b
a = B²*(1-A²/3), b = B³*(2*A³/27-A/3)
```

The lifted input and hinted result are checked on the selected curve. A short
scalar decomposition satisfies `s*a2+a1=0` modulo the selected prime subgroup
order, with a sign incorporated in `a2`. Both magnitudes are bounded below
`2^127`, and `a2` is nonzero. A radix-four joint checker proves
`[a1]Q+[a2]R=0`. Because `R` is also constrained to the prime subgroup,
this uniquely binds `R=[s]Q`.

The checker uses the lazy affine ladder in
[`internal/shortw`](../internal/shortw): the affine arithmetic, packed lookup
tables, balanced slopes and projected field reductions use curve coefficients and hints supplied by the checker. X25519 adds exact slope
guards that accept native-field aliases and a packed distinct-X guard that
needs no canonicalization. The sole initial exceptional scalar
in the clamped interval, `s=1/3`, is routed through `[s/2](2Q)` using selected
constant `1/6`.

Rational reconstruction produces coprime magnitudes, so the circuit requires
at least one magnitude to be odd. Euclid's coefficient row is primitive;
a common factor of the returned numerator and denominator would therefore
divide the prime subgroup order, contradicting their bounds. Write `R_s` for
the sign-adjusted result point. The uncorrected ladder accumulator equals
`[3]R_s`, `[4]R_s`, or `Q+[3]R_s`, selected by the two parity bits. The latter
point is already in the lookup table. The fourth multiple is a checked sum of
`[3]R_s` and `R_s`; their x-coordinates differ because the subgroup order
exceeds four. Direct equality to this known on-curve target supplies the final
membership needed by the backward proof, without corrections that could erase
an off-curve residual. A single-step harness admits an off-curve equal-point step only when its
copy of this target equality is removed.

## Subgroup binding and zero denominators

Curve and twist orders are `8*l` and `4*l'`, where:

```
l  = 2^252 + 27742317777372353535851937790883648493
l' = 2^253 - 55484635554744707071703875581767296995
```

Both primes exceed `2^252`, and `s` lies in `[2^251,2^252)`. The initial three
doublings clear either cofactor. To bind the hinted result to its subgroup,
the circuit hints an x-coordinate `w` and checks `[8]w=u(R)` using three more
x-only doublings. Every field x-coordinate lifts to the curve or twist, and
doubling preserves that class; the nonzero result's checked curve membership
therefore fixes the root's class without a root y-coordinate witness.

Each doubling hints `r,t` and checks, modulo `p=2^255-19`:

```
t*x = x²+1
4*r*(t+A) = t²-4
```

`x=0` contradicts the first equation. For nonzero `x`, the first fixes `t`;
`t=-A` contradicts the second because `A²!=4`. Zero denominators therefore
cannot produce unconstrained coordinates. Low-order inputs are rejected by
constraints even if honest hint errors are replaced with malicious values.

The joint ladder's backward curve-membership argument is the polynomial
argument in [the ladder notes](../internal/shortw/ladder-soundness.md), with general
`a,b`. Its nonzero-y argument also holds on these cofactor curves: an on-curve
point with `y=0` and a satisfied tangent relation would be a repeated root of
the curve cubic, contradicting nonsingularity. At a doubled point with `y=0`,
the nonzero second slope forces equal intermediate x-coordinates; the pinned
curve residual then again forces that repeated-root contradiction. Thus every
checked operation is a group operation, and the prime-subgroup input/table
points keep all successful accumulators in the subgroup.

The output is constrained to a nonzero canonical value below `p` and encoded
as 32 little-endian bytes. Hints use `math/big`; they do not provide
constant-time native key agreement.

## Validation and reproduction

```sh
go test ./x25519/...
go run ./cmd/benchmark -only X25519 -out x25519/BENCHMARKS.md
```

Tests include both RFC vectors, arbitrary curve/twist inputs, scalar extremes,
noncanonical peer aliases, high-bit masking, byte-range failures, low-order
peers, 238 small rational scalar cases, and malicious result, scalar, subgroup,
curve-selector and slope hints. The curve and twist torsion-shift forgeries
satisfy the whole short relation whenever the reconstructed denominator is even, so only the subgroup
equality rejects them; the regressions check that the rejection is a
constraint failure. Low-order peers are also rejected with a doubling hint
that returns zeros instead of an error.

The initial projective ladder used 103,351 constraints; an optimized direct
affine ladder used 54,298. Experiments compared field layouts, range-table
sizes, balanced helpers, lazy polynomial equations and short relations.

Sources: [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html),
[Montgomery curves and their arithmetic](https://arxiv.org/html/1703.01863),
[Montgomery formulas](https://www.hyperelliptic.org/EFD/g1p/auto-montgom-xz.html),
and [fake GLV](https://ethresear.ch/t/fake-glv-you-dont-need-an-efficient-endomorphism-to-implement-glv-like-scalar-multiplication-in-snark-circuits/20394).

Imported from `gnark-gadgets/x25519` at experiments commit `ddb69ff`.
