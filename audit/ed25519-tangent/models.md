# Constraint implication

Let `F(x,y)=y²-x³-a*x-b`. A step receives accumulator `P=(X,Y)` and on-curve table point `T=(u,v)`. All equations below are modulo the Curve25519 prime p.

The first slope alpha satisfies `2*alpha*Y=3*X²+a`; the doubled coordinates are `x=alpha²-2X`, `y=alpha*(X-x)-Y`. Exact expansion gives `F(x,y)=F(X,Y)` even when the input is off curve.

The remaining constraints, after using the chord equation, are:

```
lambda*(u-x) = v-y
z = lambda²-x-u
mu*(z-x) = 2y
w = u+mu*(mu+2lambda)
r = (lambda+mu)*(w-x)-y
K = (z-x)*(u-x+lambda*mu)-3x²-a
```

Symbolic expansion proves:

```
F(u,v)-F(x,y) = (u-x)*K
F(w,r)-F(x,y) = (w-x)*K
F(w,r)-F(u,v) = (w-u)*K
```

The old guards prove `mu != 0` and `mu+2lambda != 0` modulo p. Therefore `w-u != 0`. If the output is on curve, and the table point is on curve, the third identity forces `K=0`. The first identity forces `F(x,y)=0`, and the doubling identity forces `F(X,Y)=0`.

The final curve assertion anchors this argument. Backward induction across all 63 steps proves every accumulator and doubled point is on curve and every step has K=0. This covers arbitrary malicious choices of every hint in every step, not only an honest hint after one modified step.

At coincident x coordinates, `u=x`, the chord equation gives `v=y`. Substituting `mu*(z-x)=2y` into K gives `K=2*lambda*y-3*x²-a`. Thus K=0 is exactly the newly added tangent equation.

No zero-denominator exception remains. On-curve `(X,Y)` with Y=0 could satisfy the tangent equation only at a singular point. For `(x,y)`, y=0 and the second slope relation, with mu nonzero, force z=x; then K=0 forces `3x²+a=0`, also singular. Consequently both tangent and second-slope denominators are nonzero. At distinct x, the chord fixes lambda; at coincident x, the derived tangent relation fixes lambda. The output is the finite group sum 4P+T.

## Native-field guards

HintBalanced enforces six signed limbs with widths `[43,43,43,43,43,40]`. Their base-2^43 integer has absolute value below p, verified by exact integer bounds. The balanced digit intervals have unique representation, so the two packed halves are both zero exactly when the slope integer is zero. The inverse certificate on those halves proves mu is nonzero modulo p.

For `S=mu+2lambda`, the absolute bound is below 2p. A value zero modulo p is therefore exactly -p, 0 or p as an integer. The native predicate `z=IsZero(S*(S-p)*(S+p))` detects these, as well as possible native-q aliases. When z=1, the two carry equations imply `k*p=S (mod q)`, forcing k to -1, 0 or 1 in Fq. The bounded carry and n then lift both half equations to integer equalities: `S=k*p+n*q`. The certificate `n*inv=z` requires n nonzero, excluding the actual -p, 0, p cases, while admitting nonzero native aliases. This does not trust slopeAliasHint's suggested k or n. Exact lift bounds are checked by `check_identities.py`; 69 alias witnesses and a forged correction are exercised in the solver.

## Flow and applicability

Signature points and fixed offset -> curve-checked coordinate conversion -> guarded table additions -> committed table row selection -> 63 lazy steps with both slope guards -> terminal reduction preserving residues -> final curve assertion.

There is no protocol state transition in this review. Privacy and public-input shape are unchanged: the removed block adds only internal witnesses and constraints. A standalone step without the terminal-anchor contract does not satisfy this proof; the unanchored negative control intentionally accepts a forged output.
