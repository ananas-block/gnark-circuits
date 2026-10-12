// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package p256

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc/secp256r1"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/internal/lookup"
	"github.com/ananas-block/gnark-circuits/p256/emfield"
)

func init() {
	solver.RegisterHint(p256DecomposeScalarHint, p256ScalarMulHint, p256ImplicitChordHint, p256ImplicitSecondSlopeHint)
}

const (
	halfScalarBits = 129
	packedXGroup   = 2
	packedYGroup   = 3
)

func (c *curve) nativeValue(e *fpElement) frontend.Variable {
	sum := frontend.Variable(0)
	for i, l := range e.Limbs() {
		sum = c.api.Add(sum, c.api.Mul(l, pow2(c.lay.LimbBits*i)))
	}
	return sum
}

func (c *curve) xDifferenceSquares(p, q *fpElement) frontend.Variable {
	widths := c.fp.ReducedWidths()
	if !p.IsReduced(widths) || !q.IsReduced(widths) {
		panic("distinct-x guard needs reduced coordinates")
	}
	c.fp.AssertCanonical(p)
	c.fp.AssertCanonical(q)
	// Each difference is at most 2^32-1 in magnitude. The sum of eight
	// squares fits the native field and is zero exactly when all limbs agree.
	sum := frontend.Variable(0)
	for i, a := range p.Limbs() {
		d := c.api.Sub(a, q.Limbs()[i])
		sum = c.api.Add(sum, c.api.Mul(d, d))
	}
	return sum
}

func (c *curve) assertDistinctX(p, q *fpElement) {
	c.api.AssertIsDifferent(c.xDifferenceSquares(p, q), 0)
}

func (c *curve) quadrupleAndAddLazy(a, t *point) *point {
	fp := c.fp
	lambda0 := c.tangent(a)
	xD := fp.Lazy(T(1, lambda0, lambda0), T(-2, a.X))
	tMinusD := fp.Sub(t.X, xD)
	lambda1 := c.slope(p256ImplicitChordHint, 1, nil, lambda0, a.X, xD, a.Y, t.X, t.Y)[0]
	yChord := fp.Lazy(T(1, lambda1, tMinusD))
	fp.AssertZeroProjected(T(1, yChord), T(1, lambda0, fp.Sub(a.X, xD)), T(-1, a.Y), T(-1, t.Y))
	x2 := fp.Lazy(T(1, lambda1, lambda1), T(-1, xD), T(-1, t.X))
	mu := c.slope(p256ImplicitSecondSlopeHint, 1, nil, lambda0, a.X, xD, a.Y, x2)[0]
	fp.AssertZeroProjected(T(1, mu, fp.Sub(x2, xD)), T(2, lambda1, tMinusD), T(-2, t.Y))
	c.assertLadderOutputDistinct(lambda1, mu)
	eta := fp.Add(lambda1, mu)
	x3 := fp.Lazy(T(1, eta, eta), T(-1, lambda1, lambda1), T(1, t.X))
	y3 := fp.Lazy(T(1, eta, fp.Sub(x3, xD)), T(1, yChord), T(-1, t.Y))
	return &point{X: x3, Y: y3}
}

func (c *curve) guardedAdd(p, q *point) *point {
	c.assertDistinctX(p.X, q.X)
	return c.add(p, q)
}

func (c *curve) scalarMulChecked(q *point, s *frElement) *point {
	// The short ladder excludes ±1, ±3 and ±1/3. For these scalars,
	// [s]Q = [s/2](2Q), and s/2 is outside that exceptional set.
	// Canonical scalar limbs make the equality flags integer-exact.
	s = c.fr.Eval(T(1, s))
	c.fr.AssertCanonical(s)
	n := GroupOrder()
	third := new(big.Int).ModInverse(big.NewInt(3), n)
	exceptional := frontend.Variable(0)
	for _, k := range []*big.Int{big.NewInt(1), big.NewInt(3), third} {
		for _, value := range []*big.Int{k, new(big.Int).Sub(n, k)} {
			limbs := c.fr.Const(value).Limbs()
			sum := frontend.Variable(0)
			for i, l := range s.Limbs() {
				d := c.api.Sub(l, limbs[i])
				sum = c.api.Add(sum, c.api.Mul(d, d))
			}
			exceptional = c.api.Add(exceptional, c.api.IsZero(sum))
		}
	}
	half := c.fr.Eval(T(1, s, c.fr.Const(new(big.Int).ModInverse(big.NewInt(2), n))))
	return c.scalarMulLadder(c.selectPoint(exceptional, c.double(q), q), c.fr.Select(exceptional, half, s))
}

func (c *curve) scalarMulLadder(q *point, s *frElement) *point {
	fr, fp, api := c.fr, c.fp, c.api
	decomposition, err := api.Compiler().NewHint(p256DecomposeScalarHint, 1+2*halfScalarBits, c.limbHintInputs(s.Limbs())...)
	if err != nil {
		panic(fmt.Sprintf("decompose hint: %v", err))
	}
	sign := decomposition[0]
	api.AssertIsBoolean(sign)
	s1bits := decomposition[1 : 1+halfScalarBits]
	s2bits := decomposition[1+halfScalarBits:]
	// Bits above bit 0 are consumed only through their radix-four digit.
	// Bounding the digit is sufficient; the constituent hint values need
	// not themselves be Boolean. Keep the hint's existing output shape.
	s1digits := c.radixFourDigits(s1bits)
	s2digits := c.radixFourDigits(s2bits)
	s1Top, s2Top := s1digits[len(s1digits)-1], s2digits[len(s2digits)-1]
	s1 := c.scalarFromRadixFour(s1bits[0], s1digits)
	s2 := c.scalarFromRadixFour(s2bits[0], s2digits)
	api.AssertIsDifferent(api.Add(s2bits[0], s2digits[0], s2digits[1:]...), 0)
	fr.AssertZero(T(1, s, fr.Select(sign, fr.Neg(s2), s2)), T(1, s1))

	hinted := fp.Hint(p256ScalarMulHint, 2, nil, q.X, q.Y, s)
	r := &point{X: hinted[0], Y: hinted[1]}
	c.assertOnCurve(r)

	q3 := c.triple(q)
	rSigned := &point{X: r.X, Y: fp.Select(sign, fp.Neg(r.Y), r.Y)}
	r3 := c.triple(rSigned)
	c.assertDistinctX(r.X, q.X)
	c.assertDistinctX(r.X, q3.X)
	c.assertDistinctX(r3.X, q.X)
	negQ := c.neg(q)
	negR := c.neg(rSigned)

	acc := c.add(q, rSigned)
	t1 := c.add(q3, r3)
	t2 := acc
	t3 := c.add(q3, rSigned)
	t4 := c.add(q, r3)
	t12 := c.add(negR, q)
	negR3 := c.neg(r3)
	slots := []*point{t1, c.add(q, negR3), c.add(q3, negR), t2, t4, c.add(q3, negR3), t12, t3}
	// Rational reconstruction returns two 128-bit halves, so their unused
	// bit 128 is zero. The first quadruple-and-add therefore equals one of
	// these four already checked table points, selected by bit 127.
	acc = c.selectPoint(s2Top, c.selectPoint(s1Top, t1, t4), c.selectPoint(s1Top, t3, t2))
	lookup := c.packedTableLookup(slots, s1digits, s2digits)
	for i := halfScalarBits - 3; i > 2; i -= 2 {
		acc = c.quadrupleAndAddLazy(acc, lookup(i))
	}
	acc = c.quadrupleAndAddLazy(acc, c.guardedAdd(lookup(2), r3))
	// Together with each step's output-X guard, this propagates curve
	// membership backwards and certifies every incomplete group operation.
	// It must precede the conditional corrections, which can erase an
	// off-curve residual. See ladder-soundness.md for the exact identities.
	c.assertOnCurve(acc)
	acc = &point{X: fp.Eval(T(1, acc.X)), Y: acc.Y}

	acc = c.selectPoint(s1bits[0], acc, c.guardedAddReducing(negQ, acc, true, false))
	acc = c.selectPoint(s2bits[0], acc, c.guardedAddReducing(negR, acc, false, false))
	c.assertEqual(acc, r3)
	return r
}

func (c *curve) guardedAddReducing(p, q *point, reduceX, reduceY bool) *point {
	c.assertDistinctX(p.X, q.X)
	return c.addReducing(p, q, reduceX, reduceY)
}

func (c *curve) scalarFromBits(bits []frontend.Variable) *frElement {
	var limbs []frontend.Variable
	var widths []int
	for i := 0; i < len(bits); i += c.lay.LimbBits {
		chunk := bits[i:min(len(bits), i+c.lay.LimbBits)]
		limbs = append(limbs, c.api.FromBinary(chunk...))
		widths = append(widths, len(chunk))
	}
	return c.fr.Bounded(limbs, widths)
}

func (c *curve) radixFourDigits(bits []frontend.Variable) []frontend.Variable {
	c.api.AssertIsBoolean(bits[0])
	digits := make([]frontend.Variable, (len(bits)-1)/2)
	for i := range digits {
		digits[i] = c.api.Add(bits[1+2*i], c.api.Mul(bits[2+2*i], 2))
		width := 2
		if i == len(digits)-1 {
			width = 1
		}
		c.rangeChecker().Check(digits[i], width)
	}
	return digits
}

func (c *curve) scalarFromRadixFour(low frontend.Variable, digits []frontend.Variable) *frElement {
	if c.lay.LimbBits%2 != 0 {
		panic("radix-four scalar limbs need an even width")
	}
	perLimb := c.lay.LimbBits / 2
	var limbs []frontend.Variable
	var widths []int
	for i := 0; i < len(digits); i += perLimb {
		chunk := digits[i:min(len(digits), i+perLimb)]
		sum := frontend.Variable(0)
		for j, digit := range chunk {
			sum = c.api.Add(sum, c.api.Mul(digit, pow2(2*j)))
		}
		limbs = append(limbs, sum)
		width := 2 * len(chunk)
		if i+len(chunk) == len(digits) {
			width--
		}
		widths = append(widths, width)
	}
	high := c.fr.Lin([]int64{2}, c.fr.Bounded(limbs, widths))
	return c.fr.Add(high, c.fr.Bounded([]frontend.Variable{low}, []int{1}))
}

func p256DecomposeScalarHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(outputs) != 1+2*halfScalarBits {
		return errors.New("expecting the sign and bit outputs")
	}
	s := limbHintValue(inputs)
	n := GroupOrder()
	res := lattice.NewReconstructor(n).RationalReconstruct(s.Mod(s, n))
	x, z := new(big.Int).Set(res[0]), new(big.Int).Set(res[1])
	if x.Sign() < 0 {
		x.Neg(x)
		z.Neg(z)
	}
	outputs[0].SetUint64(0)
	if z.Sign() > 0 {
		outputs[0].SetUint64(1)
	}
	z.Abs(z)
	for i := 0; i < halfScalarBits; i++ {
		outputs[1+i].SetUint64(uint64(x.Bit(i)))
		outputs[1+halfScalarBits+i].SetUint64(uint64(z.Bit(i)))
	}
	return nil
}

func p256ScalarMulHint(q *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(_ *big.Int, _, in, out []*big.Int) error {
		if len(in) != 3 || len(out) != 2 {
			return errors.New("expecting a point and a scalar")
		}
		var p secp256r1.G1Affine
		p.X.SetBigInt(in[0])
		p.Y.SetBigInt(in[1])
		p.ScalarMultiplication(&p, new(big.Int).Mod(in[2], GroupOrder()))
		p.X.BigInt(out[0])
		p.Y.BigInt(out[1])
		return nil
	})
}

func implicitDoubledY(p *big.Int, lambda0, xA, xD, yA *big.Int) *big.Int {
	y := new(big.Int).Sub(xA, xD)
	y.Mul(y, lambda0).Sub(y, yA)
	return y.Mod(y, p)
}

func modRatio(p, num, den *big.Int) *big.Int {
	d := new(big.Int).Mod(den, p)
	if d.Sign() == 0 {
		return new(big.Int)
	}
	d.ModInverse(d, p)
	return d.Mul(d, num).Mod(d, p)
}

func p256ImplicitChordHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 6 || len(out) != 1 {
			return errors.New("expecting six inputs and one output")
		}
		yD := implicitDoubledY(p, in[0], in[1], in[2], in[3])
		dx := new(big.Int).Sub(in[4], in[2])
		dy := new(big.Int).Sub(in[5], yD)
		if new(big.Int).Mod(dx, p).Sign() == 0 && new(big.Int).Mod(dy, p).Sign() == 0 {
			// The final curve check pins the tangent in this equal-point case.
			num := new(big.Int).Mul(in[2], in[2])
			num.Sub(num, big.NewInt(1)).Mul(num, big.NewInt(3))
			out[0].Set(modRatio(p, num, new(big.Int).Lsh(yD, 1)))
			return nil
		}
		out[0].Set(modRatio(p, dy, dx))
		return nil
	})
}

func p256ImplicitSecondSlopeHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 5 || len(out) != 1 {
			return errors.New("expecting five inputs and one output")
		}
		yD := implicitDoubledY(p, in[0], in[1], in[2], in[3])
		out[0].Set(modRatio(p, yD.Lsh(yD, 1), new(big.Int).Sub(in[4], in[2])))
		return nil
	})
}

func (c *curve) packedCoordinate(e *fpElement, group int) []frontend.Variable {
	api := c.api
	limbs := e.Limbs()
	var out []frontend.Variable
	for g := 0; g < len(limbs); g += group {
		sum := frontend.Variable(0)
		for j := g; j < min(g+group, len(limbs)); j++ {
			sum = api.Add(sum, api.Mul(limbs[j], pow2(c.lay.LimbBits*(j-g))))
		}
		out = append(out, sum)
	}
	return out
}

func (c *curve) unpackedCoordinate(packed []frontend.Variable, group int, signed bool) *fpElement {
	widths := c.fp.ReducedWidths()
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
	return c.fp.WithBounds(limbs, lo, hi)
}

func (c *curve) packedTableLookup(slots []*point, s1digits, s2digits []frontend.Variable) func(i int) *point {
	api, fp := c.api, c.fp
	widths := fp.ReducedWidths()
	nbLimbs := len(widths)
	nbPackedX := (nbLimbs + packedXGroup - 1) / packedXGroup
	nbPackedY := (nbLimbs + packedYGroup - 1) / packedYGroup
	table := lookup.New(api, nbPackedX+nbPackedY)
	for idx := 0; idx < 16; idx++ {
		// The radix-four selector lists each scalar's low bit first. The
		// joint ladder's slot ordering lists the high bits first instead.
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
		row := append(c.packedCoordinate(slot.X, packedXGroup), c.packedCoordinate(y, packedYGroup)...)
		table.Insert(row)
	}
	return func(i int) *point {
		digit := (i - 2) / 2
		selector := api.Add(s1digits[digit], api.Mul(s2digits[digit], 4))
		cols := table.Lookup(selector)
		x := c.unpackedCoordinate(cols[:nbPackedX], packedXGroup, false)
		if i == 2 {
			// The final guarded addition compares reduced X coordinates.
			x = fp.Eval(T(1, x))
		}
		return &point{X: x, Y: c.unpackedCoordinate(cols[nbPackedX:nbPackedX+nbPackedY], packedYGroup, true)}
	}
}

// assertLadderOutputDistinct proves mu*(mu+2*lambda) != 0 modulo p.
// Both operands must come from HintBalanced, whose signed limb bounds imply
// |mu| <= M < p and |mu+2*lambda| <= 3M < 2p. Therefore the only integer
// representatives of zero modulo p are 0 for mu and {-p, 0, p} for the sum.
// The native polynomial rejects all of them, including aliases modulo the
// native field. A native-field collision can reject an honest witness, but
// cannot admit a zero modulo p.
func (c *curve) assertLadderOutputDistinct(lambda, mu *fpElement) {
	m := new(big.Int)
	for i, w := range c.fp.ReducedWidths() {
		m.Add(m, new(big.Int).Lsh(pow2(w-1), uint(c.lay.LimbBits*i)))
	}
	p := c.fp.Modulus()
	if m.Cmp(p) >= 0 || new(big.Int).Mul(m, big.NewInt(3)).Cmp(new(big.Int).Lsh(p, 1)) >= 0 {
		panic("ladder output guard needs balanced slope bounds")
	}
	value := c.nativeValue(mu)
	sum := c.api.Add(value, c.api.Mul(c.nativeValue(lambda), 2))
	pp := new(big.Int).Mul(p, p)
	factor := c.api.Mul(sum, c.api.Sub(c.api.Mul(sum, sum), pp))
	c.api.AssertIsDifferent(c.api.Mul(value, factor), 0)
}
