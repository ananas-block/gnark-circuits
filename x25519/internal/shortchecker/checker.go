package shortchecker

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/internal/emfield"
	"github.com/ananas-block/gnark-circuits/internal/shortw"
)

type point = shortw.Point

var T = shortw.T

// curve adds the curve/twist selector and the twist scalar field to the
// shared short-Weierstrass arithmetic.
type curve struct {
	*shortw.Curve
	twist   frontend.Variable
	outputU *emfield.Element
	frTwist *emfield.Field
}

func newCurve(api frontend.API, f *emfield.Field, a, b *emfield.Element) *curve {
	c := &curve{Curve: &shortw.Curve{API: api, Lay: f.Layout(), Fp: f, A: a, B: b, Hints: shortw.SharedHints}}
	c.OutputGuard = c.assertLadderOutputDistinct
	return c
}

func pow2(n int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n))
}

func prime() *big.Int { return new(big.Int).Sub(pow2(255), big.NewInt(19)) }
func order(twist bool) *big.Int {
	if twist {
		c, _ := new(big.Int).SetString("55484635554744707071703875581767296995", 10)
		return new(big.Int).Sub(pow2(253), c)
	}
	c, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return new(big.Int).Add(pow2(252), c)
}
func offset() *big.Int { return shortw.ModRatio(prime(), big.NewInt(486662), big.NewInt(3)) }
func coefficients(twist bool) (a, b *big.Int) {
	p := prime()
	A := big.NewInt(486662)
	a = new(big.Int).Mul(A, A)
	a.Mul(a, new(big.Int).ModInverse(big.NewInt(3), p))
	a.Sub(big.NewInt(1), a)
	b = new(big.Int).Exp(A, big.NewInt(3), p)
	b.Lsh(b, 1).Mul(b, new(big.Int).ModInverse(big.NewInt(27), p))
	b.Sub(b, offset())
	if twist {
		a.Lsh(a, 2)
		b.Lsh(b, 3)
	}
	return a.Mod(a, p), b.Mod(b, p)
}

// MultiplyScalar requires s=k/8 with the clamped integer range
// 2^251 <= s < 2^252, enforced by the caller's bounded byte packing.
func MultiplyScalar(api frontend.API, f *emfield.Field, u, s *emfield.Element) *emfield.Element {
	for i := 0; i < 3; i++ {
		u = xDouble(f, u)
	}
	raw, err := api.Compiler().NewHint(curveClassHint, 1, append([]frontend.Variable{f.Layout().LimbBits}, u.Limbs()...)...)
	if err != nil {
		panic(err)
	}
	twist := raw[0]
	api.AssertIsBoolean(twist)
	a0, b0 := coefficients(false)
	a1, b1 := coefficients(true)
	c := newCurve(api, f, f.Select(twist, f.Const(a1), f.Const(a0)), f.Select(twist, f.Const(b1), f.Const(b0)))
	c.Fr = emfield.NewFor(api, order(false), f.Layout())
	c.frTwist = emfield.NewFor(api, order(true), f.Layout())
	c.twist = twist
	B := f.Bounded([]frontend.Variable{api.Add(1, twist)}, []int{2})
	X := f.EvalProjected(T(1, B, f.Add(u, f.Const(offset()))))
	Y := f.Hint(liftHint, 1, []frontend.Variable{twist}, u)[0]
	q := &point{X: X, Y: Y}
	c.AssertOnCurve(q)
	c.scalarMulChecked(q, s)
	return c.outputU
}

// scalarZero asserts the terms vanish modulo the selected subgroup order.
func (c *curve) scalarZero(ts ...emfield.Term) {
	for i, f := range []*emfield.Field{c.Fr, c.frTwist} {
		flag := c.twist
		if i == 0 {
			flag = c.API.Sub(1, flag)
		}
		gate := f.Bounded([]frontend.Variable{flag}, []int{1})
		gated := make([]emfield.Term, len(ts))
		for j, t := range ts {
			gated[j] = emfield.Term{Coef: t.Coef, Factors: append([]*emfield.Element{gate}, t.Factors...)}
		}
		f.AssertZero(gated...)
	}
}

// scalarConst holds a scalar constant that may exceed the curve order, so it
// cannot be reduced by c.Fr. Elements are layout-generic, and the ladder only
// consumes the limbs and their bounds.
func (c *curve) scalarConst(v *big.Int) *emfield.Element {
	return c.Fp.Const(v)
}

func (c *curve) assertSubgroup(r *point) {
	f := c.Fp
	u := f.Hint(montUHint, 1, []frontend.Variable{c.twist}, r.X)[0]
	B := f.Bounded([]frontend.Variable{c.API.Add(1, c.twist)}, []int{2})
	f.AssertZeroProjected(T(1, B, f.Add(u, f.Const(offset()))), T(-1, r.X))
	w := f.Hint(rootHint, 1, []frontend.Variable{c.twist}, r.X, r.Y)[0]
	for i := 0; i < 3; i++ {
		w = xDouble(f, w)
	}
	f.AssertZeroProjected(T(1, w), T(-1, u))
	c.outputU = u
}

// xDouble is the Montgomery x-only doubling. Both hinted values are fixed by
// the equations: x=0 contradicts the first, and t=-A contradicts the second
// because A^2 != 4. Low-order inputs therefore fail by constraint.
func xDouble(f *emfield.Field, x *emfield.Element) *emfield.Element {
	o := f.Hint(xDoubleHint, 2, nil, x)
	r, t := o[0], o[1]
	one := f.Const(big.NewInt(1))
	f.AssertZeroProjected(T(1, t, x), T(-1, x, x), T(-1, one))
	f.AssertZeroProjected(T(4, r, f.Add(t, f.Const(big.NewInt(486662)))), T(-1, t, t), T(4, one))
	return r
}

func init() { solver.RegisterHint(curveClassHint, liftHint, montUHint, rootHint, xDoubleHint) }

func curveClassHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) < 2 || len(out) != 1 {
		return errors.New("class shape")
	}
	u := shortw.LimbHintValue(in)
	p := prime()
	v := new(big.Int).Mul(u, u)
	v.Add(v, new(big.Int).Mul(big.NewInt(486662), u)).Add(v, big.NewInt(1)).Mul(v, u).Mod(v, p)
	out[0].SetInt64(0)
	if big.Jacobi(v, p) < 0 {
		out[0].SetInt64(1)
	}
	return nil
}

func liftHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, n, v, o []*big.Int) error {
		if len(n) != 1 || len(v) != 1 || len(o) != 1 {
			return errors.New("lift shape")
		}
		u := v[0]
		h := new(big.Int).Mul(u, u)
		h.Add(h, new(big.Int).Mul(big.NewInt(486662), u)).Add(h, big.NewInt(1)).Mul(h, u)
		if n[0].Sign() != 0 {
			h.Lsh(h, 3)
		}
		h.Mod(h, p)
		if o[0].ModSqrt(h, p) == nil {
			return errors.New("no lift")
		}
		return nil
	})
}

func montUHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, n, v, o []*big.Int) error {
		if len(n) != 1 || len(v) != 1 || len(o) != 1 {
			return errors.New("u shape")
		}
		o[0].Set(v[0])
		if n[0].Sign() != 0 {
			o[0].Mul(o[0], new(big.Int).ModInverse(big.NewInt(2), p))
		}
		o[0].Sub(o[0], offset()).Mod(o[0], p)
		return nil
	})
}

func rootHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, n, v, o []*big.Int) error {
		if len(n) != 1 || len(v) != 2 || len(o) != 1 {
			return errors.New("root shape")
		}
		twist := n[0].Sign() != 0
		a, _ := coefficients(twist)
		r := hostMul(hostPoint{v[0], v[1]}, new(big.Int).ModInverse(big.NewInt(8), order(twist)), a)
		if r.x == nil {
			return errors.New("root infinity")
		}
		o[0].Set(r.x)
		if twist {
			o[0].Mul(o[0], new(big.Int).ModInverse(big.NewInt(2), p))
		}
		o[0].Sub(o[0], offset()).Mod(o[0], p)
		return nil
	})
}

func xDoubleHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, _, v, o []*big.Int) error {
		if len(v) != 1 || len(o) != 2 {
			return errors.New("x double shape")
		}
		x := v[0]
		xx := new(big.Int).Mul(x, x)
		h := new(big.Int).Add(xx, new(big.Int).Mul(big.NewInt(486662), x))
		h.Add(h, big.NewInt(1)).Lsh(h, 2)
		inv := new(big.Int).Mul(x, h)
		inv.Mod(inv, p)
		if inv.ModInverse(inv, p) == nil {
			return errors.New("double infinity")
		}
		num := new(big.Int).Sub(xx, big.NewInt(1))
		o[0].Mul(num, num).Mul(o[0], inv).Mod(o[0], p)
		o[1].Mul(h, inv).Add(o[1], x).Mod(o[1], p)
		return nil
	})
}

type hostPoint struct{ x, y *big.Int }

func hostAdd(p, q hostPoint, a *big.Int) hostPoint {
	if p.x == nil {
		return q
	}
	if q.x == nil {
		return p
	}
	mod := prime()
	var num, den *big.Int
	if p.x.Cmp(q.x) == 0 {
		if p.y.Cmp(q.y) != 0 || p.y.Sign() == 0 {
			return hostPoint{}
		}
		num = new(big.Int).Mul(p.x, p.x)
		num.Mul(num, big.NewInt(3)).Add(num, a)
		den = new(big.Int).Lsh(p.y, 1)
	} else {
		num = new(big.Int).Sub(q.y, p.y)
		den = new(big.Int).Sub(q.x, p.x)
	}
	l := shortw.ModRatio(mod, num, den)
	x := new(big.Int).Mul(l, l)
	x.Sub(x, p.x).Sub(x, q.x).Mod(x, mod)
	y := new(big.Int).Sub(p.x, x)
	y.Mul(y, l).Sub(y, p.y).Mod(y, mod)
	return hostPoint{x, y}
}
