package x25519

import (
	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/internal/emfield"
	"github.com/ananas-block/gnark-circuits/x25519/internal/shortchecker"
)

// ScalarMulGenerator derives the canonical 32-byte X25519 public key from a
// byte-constrained private scalar, including RFC 7748 clamping.
func ScalarMulGenerator(api frontend.API, scalar [32]frontend.Variable) [32]frontend.Variable {
	requireBN254(api)
	return scalarMulGenerator(api, scalarBits(api, scalar))
}

// scalarMulGenerator takes the 252 constrained clamped scalar bits.
func scalarMulGenerator(api frontend.API, bits []frontend.Variable) [32]frontend.Variable {
	lay := defaultLayout
	// Fixed-base constant selection favors six 43-bit limbs. Keep the raw
	// checker's piece width so both operations share one range-check table.
	lay.NbLimbs, lay.LimbBits = 6, 43

	f := emfield.NewFor(api, prime(), lay)
	result := shortchecker.MultiplyBase(api, f, bits)
	f.AssertCanonical(result)
	return outputBytes(api, f, result)
}
