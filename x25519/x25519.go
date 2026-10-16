package x25519

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/internal/emfield"
	"github.com/ananas-block/gnark-circuits/x25519/internal/shortchecker"
)

func prime() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
}

var defaultLayout = emfield.Layout{NbLimbs: 7, LimbBits: 37, PieceBits: 10}

func requireBN254(api frontend.API) {
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		panic("x25519: BN254 native field required")
	}
}

func ECDH(api frontend.API, scalar, peer [32]frontend.Variable) [32]frontend.Variable {
	requireBN254(api)
	f := emfield.NewFor(api, prime(), defaultLayout)
	s := clampedScalarFromBytes(api, f, scalar)

	return ecdh(api, f, s, peer)
}

func ecdh(api frontend.API, f *emfield.Field, s *emfield.Element, peer [32]frontend.Variable) [32]frontend.Variable {
	values, widths := make([]frontend.Variable, 32), make([]int, 32)
	for i := 0; i < 31; i++ {
		f.RangeChecker().Check(peer[i], 8)
		values[i], widths[i] = peer[i], 8
	}
	_, values[31] = splitByte(api, f, peer[31], 7, 8)
	widths[31] = 7
	u := packSegments(api, f, values, widths)

	shared := shortchecker.MultiplyScalar(api, f, u, s)
	f.AssertCanonical(shared)
	return outputBytes(api, f, shared)
}

func clampedScalarFromBytes(api frontend.API, f *emfield.Field, scalar [32]frontend.Variable) *emfield.Element {
	values, widths := make([]frontend.Variable, 32), make([]int, 32)
	values[0], _ = splitByte(api, f, scalar[0], 3, 8)
	widths[0] = 5
	for i := 1; i < 31; i++ {
		f.RangeChecker().Check(scalar[i], 8)
		values[i], widths[i] = scalar[i], 8
	}
	_, top := splitByte(api, f, scalar[31], 6, 8)
	values[31] = api.Add(top, 64)
	widths[31] = 7
	return packSegments(api, f, values, widths)
}

func scalarBits(api frontend.API, scalar [32]frontend.Variable) []frontend.Variable {
	var k []frontend.Variable
	for i := range scalar {
		k = append(k, api.ToBinary(scalar[i], 8)...)
	}
	k[254] = 1
	return k[3:255]
}

func clampedScalarFromBits(api frontend.API, f *emfield.Field, bits []frontend.Variable) *emfield.Element {
	var limbs []frontend.Variable
	var widths []int
	for i := 0; i < len(bits); i += f.Layout().LimbBits {
		chunk := bits[i:min(len(bits), i+f.Layout().LimbBits)]
		limbs = append(limbs, api.FromBinary(chunk...))
		widths = append(widths, len(chunk))
	}
	return f.Bounded(limbs, widths)
}
