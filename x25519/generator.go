package x25519

import (
	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/internal/emfield"
	"github.com/ananas-block/gnark-circuits/x25519/internal/shortchecker"
)

func ScalarMulGenerator(api frontend.API, scalar [32]frontend.Variable) [32]frontend.Variable {
	requireBN254(api)
	return scalarMulGenerator(api, scalarBits(api, scalar))
}

func scalarMulGenerator(api frontend.API, bits []frontend.Variable) [32]frontend.Variable {
	lay := defaultLayout

	lay.NbLimbs, lay.LimbBits = 6, 43

	f := emfield.NewFor(api, prime(), lay)
	result := shortchecker.MultiplyBase(api, f, bits)
	f.AssertCanonical(result)
	return outputBytes(api, f, result)
}
