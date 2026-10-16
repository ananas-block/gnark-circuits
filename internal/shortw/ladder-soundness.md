# Lazy affine ladder residual argument

`Curve.QuadrupleAndAddLazy` constrains a `4A+T` step through implicit slopes.
Callers must supply a nonzero output guard and pin the terminal accumulator
to the curve. X25519 supplies exact slope guards, checked table points and
an on-curve target equality.

## Exact field identities

All equations are in the selected curve base field. Write
`F(x,y) = y² − x³ − a x − b` for general coefficients `a,b`. Membership is `F = 0`.
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
has `K=0`. X25519 pins the uncorrected accumulator directly to an on-curve
target; see [the checker notes](../../x25519/README.md).

## Zero denominators

On a nonsingular short-Weierstrass curve, an on-curve point with `y=0`
cannot satisfy the tangent relation: it would be a repeated root of the
curve cubic. The checked tangent therefore has a unique slope. For the
hidden doubled point, `mu*(z-x)=2*y` forces a nonzero second denominator;
if its y-coordinate were zero, the nonzero slope guard and residual
identity would again force a repeated root. When the first chord has equal
points, `K=0` supplies the tangent relation. Otherwise the chord equation
fixes its ordinary slope. Each accepted step is consequently `4A+T`.

The X25519 regressions in `x25519/internal/shortchecker` exercise malicious
slope hints, an off-curve coincident chord, distinct-X guards, subgroup
binding and the terminal target equality.
