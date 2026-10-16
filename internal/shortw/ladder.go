package shortw

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/internal/emfield"
	"github.com/ananas-block/gnark-circuits/internal/lookup"
)

const PackedXGroup = 2

func (c *Curve) QuadrupleAndAddLazy(a, t *Point) *Point {
	fp := c.Fp
	lambda0 := c.Tangent(a)
	xD := fp.Lazy(T(1, lambda0, lambda0), T(-2, a.X))
	tMinusD := fp.Sub(t.X, xD)
	lambda1 := c.Slope(c.Hints.Chord, 1, nil, lambda0, a.X, xD, a.Y, t.X, t.Y, c.A)[0]
	yChord := fp.Lazy(T(1, lambda1, tMinusD))
	fp.AssertZeroProjected(T(1, yChord), T(1, lambda0, fp.Sub(a.X, xD)), T(-1, a.Y), T(-1, t.Y))
	x2 := fp.Lazy(T(1, lambda1, lambda1), T(-1, xD), T(-1, t.X))
	mu := c.Slope(c.Hints.SecondSlope, 1, nil, lambda0, a.X, xD, a.Y, x2)[0]
	fp.AssertZeroProjected(T(1, mu, fp.Sub(x2, xD)), T(2, lambda1, tMinusD), T(-2, t.Y))
	c.OutputGuard(lambda1, mu)
	eta := fp.Add(lambda1, mu)
	x3 := fp.Lazy(T(1, eta, eta), T(-1, lambda1, lambda1), T(1, t.X))
	y3 := fp.Lazy(T(1, eta, fp.Sub(x3, xD)), T(1, yChord), T(-1, t.Y))
	return &Point{X: x3, Y: y3}
}

func (c *Curve) RadixFourDigits(bits []frontend.Variable) []frontend.Variable {
	c.API.AssertIsBoolean(bits[0])
	digits := make([]frontend.Variable, (len(bits)-1)/2)
	for i := range digits {
		digits[i] = c.API.Add(bits[1+2*i], c.API.Mul(bits[2+2*i], 2))
		width := 2
		if i == len(digits)-1 {
			width = 1
		}
		c.Fp.RangeChecker().Check(digits[i], width)
	}
	return digits
}

func (c *Curve) ScalarFromRadixFour(low frontend.Variable, digits []frontend.Variable) *emfield.Element {
	L := c.Lay.LimbBits
	var limbs []frontend.Variable
	var widths []int
	limb, width, index := frontend.Variable(low), 1, 0
	for j, digit := range digits {
		bit := 1 + 2*j
		for bit >= L*(index+1) {
			limbs = append(limbs, limb)
			widths = append(widths, width)
			limb, width, index = 0, 0, index+1
		}
		shift := bit - L*index
		limb = c.API.Add(limb, c.API.Mul(digit, pow2(shift)))
		width = shift + 2
		if j == len(digits)-1 {
			width--
		}
	}
	limbs = append(limbs, limb)
	widths = append(widths, width)
	return c.Fr.Bounded(limbs, widths)
}

func ImplicitDoubledY(p *big.Int, lambda0, xA, xD, yA *big.Int) *big.Int {
	y := new(big.Int).Sub(xA, xD)
	y.Mul(y, lambda0).Sub(y, yA)
	return y.Mod(y, p)
}

func ChordHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 7 || len(out) != 1 {
			return errors.New("expecting seven inputs and one output")
		}
		yD := ImplicitDoubledY(p, in[0], in[1], in[2], in[3])
		dx := new(big.Int).Sub(in[4], in[2])
		dy := new(big.Int).Sub(in[5], yD)
		if new(big.Int).Mod(dx, p).Sign() == 0 && new(big.Int).Mod(dy, p).Sign() == 0 {
			num := new(big.Int).Mul(in[2], in[2])
			num.Mul(num, big.NewInt(3)).Add(num, in[6])
			out[0].Set(ModRatio(p, num, new(big.Int).Lsh(yD, 1)))
			return nil
		}
		out[0].Set(ModRatio(p, dy, dx))
		return nil
	})
}

func SecondSlopeHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 5 || len(out) != 1 {
			return errors.New("expecting five inputs and one output")
		}
		yD := ImplicitDoubledY(p, in[0], in[1], in[2], in[3])
		out[0].Set(ModRatio(p, yD.Lsh(yD, 1), new(big.Int).Sub(in[4], in[2])))
		return nil
	})
}

func (c *Curve) PackedCoordinate(e *emfield.Element, group int) []frontend.Variable {
	api := c.API
	limbs := e.Limbs()
	var out []frontend.Variable
	for g := 0; g < len(limbs); g += group {
		sum := frontend.Variable(0)
		for j := g; j < min(g+group, len(limbs)); j++ {
			sum = api.Add(sum, api.Mul(limbs[j], pow2(c.Lay.LimbBits*(j-g))))
		}
		out = append(out, sum)
	}
	return out
}

func (c *Curve) UnpackedCoordinate(packed []frontend.Variable, group int, signed bool) *emfield.Element {
	widths := c.Fp.ReducedWidths()
	n := len(widths)
	limbs := make([]frontend.Variable, n)
	lo, hi := make([]*big.Int, n), make([]*big.Int, n)
	for j := range limbs {
		limbs[j] = 0
		lo[j], hi[j] = new(big.Int), new(big.Int)
		if j%group != 0 {
			continue
		}
		bits := 0
		for _, w := range widths[j:min(j+group, n)] {
			bits += w
		}
		limbs[j] = packed[j/group]
		hi[j].Sub(pow2(bits), big.NewInt(1))
		if signed {
			lo[j].Neg(hi[j])
		}
	}
	return c.Fp.WithBounds(limbs, lo, hi)
}

func (c *Curve) PackedTableLookup(slots []*Point, s1digits, s2digits []frontend.Variable) func(i int) *Point {
	api, fp := c.API, c.Fp
	widths := fp.ReducedWidths()
	nbLimbs := len(widths)
	nbPackedX := (nbLimbs + PackedXGroup - 1) / PackedXGroup
	nbPackedY := (nbLimbs + c.PackedYGroup() - 1) / c.PackedYGroup()
	table := lookup.New(api, nbPackedX+nbPackedY)
	for idx := 0; idx < 16; idx++ {

		bitIndex := (idx>>1)&1 | ((idx>>3)&1)<<1 | (idx&1)<<2 | ((idx>>2)&1)<<3
		sx := bitIndex
		if bitIndex >= 8 {
			sx = 15 - bitIndex
		}
		slot := slots[sx]
		if !slot.X.IsReduced(widths) || !slot.Y.IsReduced(widths) {
			panic("table points must be reduced")
		}
		y := slot.Y
		if bitIndex&1 == 0 {
			y = fp.Neg(y)
		}
		row := append(c.PackedCoordinate(slot.X, PackedXGroup), c.PackedCoordinate(y, c.PackedYGroup())...)
		table.Insert(row)
	}
	return func(i int) *Point {
		digit := (i - 2) / 2
		selector := api.Add(s1digits[digit], api.Mul(s2digits[digit], 4))
		cols := table.Lookup(selector)
		x := c.UnpackedCoordinate(cols[:nbPackedX], PackedXGroup, false)
		if i == 2 {

			x = fp.Eval(T(1, x))
		}
		return &Point{X: x, Y: c.UnpackedCoordinate(cols[nbPackedX:nbPackedX+nbPackedY], c.PackedYGroup(), true)}
	}
}

func (c *Curve) PackedYGroup() int { return min(3, 120/c.Lay.LimbBits) }
