package p256

import (
	"github.com/consensys/gnark/frontend"
)

func ScalarMulGenerator(api frontend.API, scalar [32]frontend.Variable) [65]frontend.Variable {
	c := newCurve(api)
	result := c.scalarMulBase(c.parseScalar(scalar))
	var out [65]frontend.Variable
	out[0] = frontend.Variable(0x04)
	copy(out[1:33], c.toBytes(result.X))
	copy(out[33:65], c.toBytes(result.Y))
	return out
}

func ECDH(api frontend.API, ephemeralPrivKey [32]frontend.Variable, recipientPubKey [65]frontend.Variable) [32]frontend.Variable {
	c := newCurve(api)
	q := c.parseKey(recipientPubKey)
	c.assertOnCurve(q)
	result := c.scalarMulChecked(q, c.parseScalar(ephemeralPrivKey))
	var xCoord [32]frontend.Variable
	copy(xCoord[:], c.toBytes(result.X))
	return xCoord
}
