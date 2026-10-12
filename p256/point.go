package p256

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(p256LimbBytesHint)
}

func GroupOrder() *big.Int {
	return new(big.Int).Set(emulated.P256Fr{}.Modulus())
}

func PointOnCurve(api frontend.API, publicKey [65]frontend.Variable) {
	c := newCurve(api)
	c.assertOnCurve(c.parseKey(publicKey))
}

func (c *curve) parseKey(publicKey [65]frontend.Variable) *point {
	c.api.AssertIsEqual(publicKey[0], uncompressedPrefix)
	c.checkBytes(publicKey[1:])
	p := &point{X: c.fp.Reduced(c.fieldLimbs(publicKey[1:33])), Y: c.fp.Reduced(c.fieldLimbs(publicKey[33:65]))}
	c.fp.AssertCanonical(p.X)
	c.fp.AssertCanonical(p.Y)
	return p
}

func (c *curve) checkBytes(bytes []frontend.Variable) {
	for _, b := range bytes {
		c.rangeChecker().Check(b, 8)
	}
}

func (c *curve) parseScalar(bytes [32]frontend.Variable) *frElement {
	c.checkBytes(bytes[:])
	return c.fr.Reduced(c.fieldLimbs(bytes[:]))
}

func (c *curve) toBytes(e *fpElement) []frontend.Variable {
	limbs := c.canonicalLimbs(e)
	widths := c.fp.ReducedWidths()
	rc := c.rangeChecker()
	var out []frontend.Variable
	for i := len(limbs) - 1; i >= 0; i-- {
		n := widths[i] / 8
		bytes, err := c.api.Compiler().NewHint(p256LimbBytesHint, n, limbs[i])
		if err != nil {
			panic(err)
		}
		for _, b := range bytes {
			rc.Check(b, 8)
		}
		c.api.AssertIsEqual(limbs[i], bigEndianSum(c.api, bytes))
		out = append(out, bytes...)
	}
	return out
}

func ScalarMul(api frontend.API, scalar [32]frontend.Variable, pointIn [65]frontend.Variable) [65]frontend.Variable {
	c := newCurve(api)
	q := c.parseKey(pointIn)
	c.assertOnCurve(q)
	result := c.scalarMulChecked(q, c.parseScalar(scalar))
	var out [65]frontend.Variable
	out[0] = frontend.Variable(0x04)
	copy(out[1:33], c.toBytes(result.X))
	copy(out[33:65], c.toBytes(result.Y))
	return out
}

func p256LimbBytesHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return errors.New("expecting one limb")
	}
	v := new(big.Int).Set(inputs[0])
	for i := len(outputs) - 1; i >= 0; i-- {
		outputs[i].And(v, big.NewInt(0xff))
		v.Rsh(v, 8)
	}
	return nil
}
