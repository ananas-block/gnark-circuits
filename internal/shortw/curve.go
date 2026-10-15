// Package shortw holds the short-Weierstrass affine arithmetic, hints and
// joint-ladder building blocks used by the X25519 checker.
// Callers supply the curve coefficients, the group-order field and, where a
// ladder needs them, the exceptional-case guards.
package shortw

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/internal/emfield"
)

var T = emfield.T

// Point is an affine point with lazily or fully reduced coordinates.
type Point struct {
	X, Y *emfield.Element
}

// Hints names the slope and addition hints a Curve calls. Each caller keeps
// its own registered functions so the hint identifiers stay package-scoped.
type Hints struct {
	Ratio, Tangent, Add, Chord, SecondSlope solver.Hint
}

// SharedHints wraps the hint implementations in this package.
var SharedHints = Hints{Ratio: RatioHint, Tangent: TangentHint, Add: AddHint, Chord: ChordHint, SecondSlope: SecondSlopeHint}

// Curve is y² = x³ + A·x + B over Fp with scalar field Fr.
type Curve struct {
	API         frontend.API
	Lay         emfield.Layout
	Fp          *emfield.Field
	Fr          *emfield.Field
	A           *emfield.Element
	B           *emfield.Element
	Hints       Hints
	OutputGuard func(lambda, mu *emfield.Element)
	diffSquares map[[2]*emfield.Element]*emfield.Element
}

func init() {
	solver.RegisterHint(RatioHint, TangentHint, AddHint, ChordHint, SecondSlopeHint)
}

func pow2(n int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n))
}

func (c *Curve) Neg(p *Point) *Point {
	return &Point{X: p.X, Y: c.Fp.Neg(p.Y)}
}

func (c *Curve) AssertOnCurve(p *Point) {
	x2 := c.EvalOrLazy(false, T(1, p.X, p.X))
	c.Fp.AssertZeroProjected(T(1, x2, p.X), T(1, c.A, p.X), T(1, c.B), T(-1, p.Y, p.Y))
}

func (c *Curve) Slope(fn solver.Hint, nbOutputs int, natives []frontend.Variable, elems ...*emfield.Element) []*emfield.Element {
	return c.Fp.HintBalanced(fn, nbOutputs, natives, elems...)
}

func (c *Curve) Ratio(num, den *emfield.Element) *emfield.Element {
	lambda := c.Slope(c.Hints.Ratio, 1, nil, num, den)[0]
	c.Fp.AssertZeroProjected(T(1, lambda, den), T(-1, num))
	return lambda
}

func (c *Curve) Tangent(p *Point) *emfield.Element {
	lambda := c.Slope(c.Hints.Tangent, 1, nil, p.X, p.Y, c.A)[0]
	c.Fp.AssertZeroProjected(T(2, lambda, p.Y), T(-3, p.X, p.X), T(-1, c.A))
	return lambda
}

// Add is the chord addition. It is only sound when the X coordinates differ;
// callers guard that case.
func (c *Curve) Add(p, q *Point) *Point {
	fp := c.Fp
	s := fp.Hint(c.Hints.Add, 2, nil, p.X, p.Y, q.X, q.Y)
	dx := fp.Sub(q.X, p.X)
	dy := fp.Sub(q.Y, p.Y)
	if c.diffSquares == nil {
		c.diffSquares = make(map[[2]*emfield.Element]*emfield.Element)
	}
	key := [2]*emfield.Element{p.X, q.X}
	dx2 := c.diffSquares[key]
	if dx2 == nil {
		dx2 = c.diffSquares[[2]*emfield.Element{q.X, p.X}]
	}
	if dx2 == nil {
		// Reversing the two X coordinates changes the sign of dx but
		// leaves its square, folded coefficients and interval bounds equal.
		dx2 = fp.Lazy(T(1, dx, dx))
		c.diffSquares[key] = dx2
	}
	fp.AssertZeroProjected(T(1, fp.Lin([]int64{1, 1, 1}, s[0], p.X, q.X), dx2), T(-1, dy, dy))
	fp.AssertZeroProjected(T(1, dy, fp.Sub(s[0], p.X)), T(1, fp.Add(s[1], p.Y), dx))
	return &Point{X: s[0], Y: s[1]}
}

func (c *Curve) EvalOrLazy(reduce bool, terms ...emfield.Term) *emfield.Element {
	if reduce {
		return c.Fp.EvalProjected(terms...)
	}
	return c.Fp.Lazy(terms...)
}

func (c *Curve) Triple(p *Point) *Point {
	lambda1 := c.Tangent(p)
	x2 := c.EvalOrLazy(false, T(1, lambda1, lambda1), T(-2, p.X))
	lambda2 := c.Fp.Sub(c.Ratio(c.Fp.MulConst(p.Y, 2), c.Fp.Sub(p.X, x2)), lambda1)
	x := c.Fp.EvalProjected(T(1, lambda2, lambda2), T(-1, p.X), T(-1, x2))
	y := c.Fp.EvalProjected(T(1, lambda2, c.Fp.Sub(p.X, x)), T(-1, p.Y))
	return &Point{X: x, Y: y}
}

// Double receives a nonidentity prime-subgroup point, so its result is finite.
func (c *Curve) Double(p *Point) *Point {
	lambda := c.Tangent(p)
	x := c.Fp.Eval(T(1, lambda, lambda), T(-2, p.X))
	y := c.Fp.Eval(T(1, lambda, c.Fp.Sub(p.X, x)), T(-1, p.Y))
	return &Point{X: x, Y: y}
}

func (c *Curve) SelectPoint(b frontend.Variable, p, q *Point) *Point {
	return &Point{X: c.Fp.Select(b, p.X, q.X), Y: c.Fp.Select(b, p.Y, q.Y)}
}

func (c *Curve) AssertEqual(p, q *Point) {
	c.Fp.AssertZero(T(1, p.X), T(-1, q.X))
	c.Fp.AssertZero(T(1, p.Y), T(-1, q.Y))
}

func (c *Curve) NativeValue(e *emfield.Element) frontend.Variable {
	sum := frontend.Variable(0)
	for i, l := range e.Limbs() {
		sum = c.API.Add(sum, c.API.Mul(l, pow2(c.Lay.LimbBits*i)))
	}
	return sum
}

func (c *Curve) LimbHintInputs(limbs []frontend.Variable) []frontend.Variable {
	return append([]frontend.Variable{c.Lay.LimbBits}, limbs...)
}

// LimbHintValue recomposes limbs passed after a leading limb-width input.
func LimbHintValue(inputs []*big.Int) *big.Int {
	limbBits := uint(inputs[0].Uint64())
	s := new(big.Int)
	for i := len(inputs) - 1; i >= 1; i-- {
		s.Lsh(s, limbBits).Add(s, inputs[i])
	}
	return s
}

func ModRatio(p, num, den *big.Int) *big.Int {
	d := new(big.Int).Mod(den, p)
	if d.Sign() == 0 {
		return new(big.Int)
	}
	d.ModInverse(d, p)
	return d.Mul(d, num).Mod(d, p)
}

func RatioHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 2 || len(out) != 1 {
			return errors.New("expecting two inputs and one output")
		}
		out[0].Set(ModRatio(p, in[0], in[1]))
		return nil
	})
}

func AddHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 4 || len(out) != 2 {
			return errors.New("expecting two points and two outputs")
		}
		lambda := ModRatio(p, new(big.Int).Sub(in[3], in[1]), new(big.Int).Sub(in[2], in[0]))
		out[0].Mul(lambda, lambda).Sub(out[0], in[0]).Sub(out[0], in[2]).Mod(out[0], p)
		out[1].Sub(in[0], out[0]).Mul(out[1], lambda).Sub(out[1], in[1]).Mod(out[1], p)
		return nil
	})
}

// TangentHint receives x, y and the curve coefficient a.
func TangentHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 3 || len(out) != 1 {
			return errors.New("expecting three inputs and one output")
		}
		num := new(big.Int).Mul(in[0], in[0])
		num.Mul(num, big.NewInt(3)).Add(num, in[2])
		out[0].Set(ModRatio(p, num, new(big.Int).Lsh(in[1], 1)))
		return nil
	})
}
