package shortchecker

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/internal/emfield"
	"github.com/ananas-block/gnark-circuits/internal/r1c"
	"github.com/ananas-block/gnark-circuits/internal/shortw"
)

func init() {
	solver.RegisterHint(shortDecomposeScalarHint, shortScalarMulHint)
}

const halfScalarBits = 129

func (c *curve) assertDistinctX(a, b *emfield.Element) {
	widths := c.Fp.ReducedWidths()
	if !a.IsReduced(widths) || !b.IsReduced(widths) {
		panic("x25519: distinct point guard needs reduced coordinates")
	}
	pack := func(e *emfield.Element, start, end int) frontend.Variable {
		out := frontend.Variable(0)
		for i := start; i < end; i++ {
			out = c.API.Add(out, c.API.Mul(e.Limbs()[i], pow2((i-start)*c.Lay.LimbBits)))
		}
		return out
	}
	cut := (c.Lay.NbLimbs + 1) / 2
	B := pow2(cut * c.Lay.LimbBits)
	mask := new(big.Int).Sub(B, big.NewInt(1))
	p := prime()
	pl := new(big.Int).And(p, mask)
	ph := new(big.Int).Rsh(p, uint(cut*c.Lay.LimbBits))
	lo := c.API.Sub(pack(a, 0, cut), pack(b, 0, cut))
	hi := c.API.Sub(pack(a, cut, c.Lay.NbLimbs), pack(b, cut, c.Lay.NbLimbs))

	for _, k := range []int64{-1, 0, 1} {
		dl := c.API.Sub(lo, new(big.Int).Mul(big.NewInt(k), pl))
		dh := c.API.Sub(hi, new(big.Int).Mul(big.NewInt(k), ph))
		inv, err := c.API.Compiler().NewHint(shortPackedNonzeroHint, 2, dl, dh)
		if err != nil {
			panic(err)
		}
		r1c.AssertProduct(c.API, inv[1], dh, c.API.Sub(1, c.API.Mul(inv[0], dl)))
	}
}

func (c *curve) guardedAdd(p, q *point) *point {
	c.assertDistinctX(p.X, q.X)
	return c.Add(p, q)
}

func (c *curve) scalarMulChecked(q *point, s *emfield.Element) *point {
	native := c.NativeValue(s)
	third0 := new(big.Int).ModInverse(big.NewInt(3), order(false))
	third1 := new(big.Int).ModInverse(big.NewInt(3), order(true))
	selected := c.API.Select(c.twist, third1, third0)
	exceptional := c.API.IsZero(c.API.Sub(native, selected))
	sixth0 := new(big.Int).ModInverse(big.NewInt(6), order(false))
	sixth1 := new(big.Int).ModInverse(big.NewInt(6), order(true))
	half := c.Fp.Select(c.twist, c.scalarConst(sixth1), c.scalarConst(sixth0))
	return c.scalarMulLadder(c.SelectPoint(exceptional, c.Double(q), q), c.Fp.Select(exceptional, half, s))
}

func (c *curve) scalarMulLadder(q *point, s *emfield.Element) *point {
	fr, fp, api := c.Fr, c.Fp, c.API
	decomposition, err := api.Compiler().NewHint(shortDecomposeScalarHint, 1+2*halfScalarBits, append([]frontend.Variable{c.twist}, c.LimbHintInputs(s.Limbs())...)...)
	if err != nil {
		panic(fmt.Sprintf("decompose hint: %v", err))
	}
	sign := decomposition[0]
	api.AssertIsBoolean(sign)
	s1bits := decomposition[1 : 1+halfScalarBits]
	s2bits := decomposition[1+halfScalarBits:]

	s1digits := c.RadixFourDigits(s1bits)
	s2digits := c.RadixFourDigits(s2bits)
	s1Top, s2Top := s1digits[len(s1digits)-1], s2digits[len(s2digits)-1]
	s1 := c.ScalarFromRadixFour(s1bits[0], s1digits)
	s2 := c.ScalarFromRadixFour(s2bits[0], s2digits)
	api.AssertIsDifferent(api.Add(s2bits[0], s2digits[0], s2digits[1:]...), 0)

	c.scalarZero(T(1, s, fr.Select(sign, fr.Neg(s2), s2)), T(1, s1))

	hinted := fp.Hint(shortScalarMulHint, 2, []frontend.Variable{c.twist}, q.X, q.Y, s)
	r := &point{X: hinted[0], Y: hinted[1]}
	c.AssertOnCurve(r)
	c.assertSubgroup(r)

	q3 := c.Triple(q)
	rSigned := &point{X: r.X, Y: fp.Select(sign, fp.Neg(r.Y), r.Y)}
	r3 := c.Triple(rSigned)

	r4 := c.Add(r3, rSigned)
	c.assertDistinctX(r.X, q.X)
	c.assertDistinctX(r.X, q3.X)
	c.assertDistinctX(r3.X, q.X)
	negR := c.Neg(rSigned)

	acc := c.Add(q, rSigned)
	t1 := c.Add(q3, r3)
	t2 := acc
	t3 := c.Add(q3, rSigned)
	t4 := c.Add(q, r3)
	t12 := c.Add(negR, q)
	negR3 := c.Neg(r3)
	slots := []*point{t1, c.Add(q, negR3), c.Add(q3, negR), t2, t4, c.Add(q3, negR3), t12, t3}

	api.AssertIsEqual(s1Top, 0)
	api.AssertIsEqual(s2Top, 0)
	acc = t2
	lookup := c.PackedTableLookup(slots, s1digits, s2digits)

	for i := halfScalarBits - 3; i > 2; i -= 2 {
		acc = c.QuadrupleAndAddLazy(acc, lookup(i))
	}
	acc = c.QuadrupleAndAddLazy(acc, c.guardedAdd(lookup(2), r3))

	api.AssertIsDifferent(api.Add(s1bits[0], s2bits[0]), 0)
	target := c.SelectPoint(s1bits[0], c.SelectPoint(s2bits[0], r3, r4), t4)
	c.AssertEqual(acc, target)
	return r
}

func shortDecomposeScalarHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(outputs) != 1+2*halfScalarBits {
		return errors.New("expecting the sign and bit outputs")
	}
	s := shortw.LimbHintValue(inputs[1:])
	n := order(inputs[0].Sign() != 0)
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

func shortScalarMulHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, n, in, out []*big.Int) error {
		if len(n) != 1 || len(in) != 3 || len(out) != 2 {
			return errors.New("scalar mul shape")
		}
		a, _ := coefficients(n[0].Sign() != 0)
		r := hostMul(hostPoint{in[0], in[1]}, in[2], a)
		if r.x == nil {
			return errors.New("scalar mul infinity")
		}
		out[0].Set(r.x)
		out[1].Set(r.y)
		return nil
	})
}
