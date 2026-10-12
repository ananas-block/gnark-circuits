# Joint-step identities and exact guards

Checked: `check-identities.py` verifies these universal identities by exact rational polynomial expansion. Let F(x,y)=y²−x³−a·x−b. The tangent certificate gives F(D)=F(P). For D=(d,yd), table point T=(t,ty), first slope l and second advice m, the existing certificates give:

- ty=l(t−d)+yd
- 2yd=m(l²−2d−t)
- Delta=m(m+2l)
- xout=t+Delta
- yout=(l+m)(xout−d)−yd

Define Q=t²+t·d+d²+a−2l·yd−l²(t−d). Then:

`F(D)−F(T)=(t−d)Q`

`F(out)−F(T)=−Delta·Q`

Table points are constrained prime-order points. A final reduced cubic assertion F(out)=0 and nonzero Delta imply Q=0, hence F(P)=0 backwards for all steps. Starting from the constrained initial table point, forward prime-group induction determines the tangent; when D=T, Q=0 determines l as the true tangent. D=−T violates the first chord certificate. The second certificate then forces its denominator nonzero and determines the final addition.

Checked slope guard: balanced limbs encode an integer in [−O,2^255−1−O], with |m|<p and |m+2l|<2p. The code checks these inequalities, 3p<8q, and conservative packed-half lifting bounds. m!=0 is checked using two small signed packed halves. For S=m+2l, let z be the native zero test of S(S−p)(S+p). If z=0, S!=0 modp. If z=1, packed equations enforce S=k·p+n·q, with n in [−8,7], n·inv=z, and bounded carry. Combining the native equations with z's cubic implies k∈{−1,0,1} in the native field; the small bounds lift both half equations to integers. Nonzero n excludes true S=0,±p while accepting every legitimate native-field alias. `TestSlopeGuardNativeAliases` exercises 69 boundary/alias cases.

Checked reduced-coordinate guard: both coordinates lie in [0,2^255). Equality modulo p occurs only at difference 0 or ±p. Because p=2^255−19, the three unborrowed packed low/high pairs are exhaustive; an alternate borrow would need an impossible high difference of±2^(255−cut). Each pair is excluded by a native two-component Bezout certificate.

SHA-512 parity sharing: for Boolean a,b,c, `a+b+c−XOR(a,b,c)=2*Maj(a,b,c)`
and `b+c+XOR(a,c)−XOR(a,b)=2*Ch(a,b,c)`. Weighted sums with powers of two
preserve these identities as integers. Byte lookup rows bind the dense and
sparse words; 13 ten-bit parity chunks recompose below 2^130. The resulting
numerators are nonnegative, even and below 2^65, so native inverse-two
multiplication is exact integer halving. Padding-boundary, malformed-byte,
wrong-digest and forged-chunk tests exercise the final implementation.

CRT squares: in a binomial quadratic factor X²=d, let w=ab and
z=(a+b)(a+db). Then `(a+bX)^2 = z−(1+d)w+2wX`. The shortcut is enabled
only when every CRT factor is a binomial quadratic; projection and combining
coefficients are verified at basis construction. Random/edge native vectors
are compared against independent convolution and monic long division, with
incorrect output coefficients rejected. Generic fallback shapes are tested.
The joint output identity `mu*(mu+2lambda)=(mu+lambda)^2−lambda^2` reuses the
existing lambda square without changing the checked polynomial.

Canonical native gap: reduced limb widths give 0≤x<B=2^bitlen(m).
When B<q and q+m≥2B, x<m gives 0≤m−1−x<B. Otherwise its native
representative is q+m−1−x≥q+m−B≥B, so a bitlen(m)-bit range check
rejects it. The inequalities are checked before enabling this shortcut;
the generic split-limb certificate remains available for other moduli.

For Boolean bits, the indicator for index i is the product of b_j where
i_j=1 and (1−b_j) where i_j=0. Expanding the latter factors by
inclusion-exclusion lets all indicators share the monomials. Their values
are exactly one-hot; the exhaustive selector test checks all widths 0..8.

A signed w-bit odd window represents d=2i−2^w+1. If the high bit of i
is set, positive-magnitude index k is its low w−1 bits. Otherwise k is
their complement and d=−(2k+1). Edwards negation (−x,y) maps to equal
Montgomery x and negated Montgomery y. Thus a half-sized positive table
plus signed y selection binds exactly the original signed odd multiple.
Packed y bounds expand symmetrically around zero and remain checked by
the existing foreign-field coefficient/carry machinery.

SHA rotation slicing: let each slice s_i have its exact width w_i, and
o_i=Σ(j<i)w_j, with Σw_i=64. Typed lookup membership gives
0≤s_i<2^w_i and its base-four spread. Thus dense and sparse sums fit below
2^64 and 2^128. Every rotation cut n is a boundary in the selected family;
the low spread is exactly the sum of slices with o_i<n. Subtracting it,
dividing by 2^(2n), and adding the rotated low spread is the exact bit
rotation in base four. Input-byte membership and exact joins bind the
original input. Generated-word sums bind the low 64 bits through a
four-bit carry; all sides lift below 2^68. One-bit and eight-bit forged
slice carries preserve the join, and a top-slice overflow preserves the
adder equation, but precise width constraints reject all three attacks.

Aligned quadratic products: in each CRT factor X²=d, use W=uu′, V=vv′, U=(u+Bv)(u′+Bv′), B=2^43. The product is real=W+dV and imag=(U−W−B²V)/B. For old 0,+1,−1 combination weights c0,c1,c2, let alpha=c0+c1+c2, beta=c1−c2, delta=c1+c2. New weights are alpha−beta/B, delta−B*beta, beta/B. Every complete tensor coefficient is verified exactly at construction. Original square blocks are retained independently. Native/even-prefix projections cancel W; later full coordinates add only missing W products through the same cache.

Projected certificates use the same result, quotient and carry bounds as full coefficients. They are enabled only when the entire checked prefix fits one existing carry group. The native quotient remains range checked; removing its bound admits a canonical wrong remainder despite tiny low carry. Both positive/negative and lookup/plain modes reject that alias.

Balanced carry coefficients represent the same integer modulus. For six 43-bit limbs, p=[−19,0,0,0,0,2^40]. Bounds use absolute values of these coefficients, and both ordinary and projected low certificates subtract these exact coefficients. The original modulus still determines hints and the native quotient. No integer lift bound is removed.

Correlated lazy bounds expand only exact recorded linear expressions, collect identical monomials and intersect their interval bounds with the original factored intervals. Native computation remains factored. Scalar extraction commutes with folding for a degree-zero factor; it reuses bilinear/square products before scaling coefficients.
