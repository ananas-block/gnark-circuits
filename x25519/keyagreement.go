package x25519

import (
	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/internal/emfield"
)

type KeyAgreement struct {
	RecipientLo frontend.Variable
	RecipientHi frontend.Variable
	EphemeralLo frontend.Variable
	EphemeralHi frontend.Variable
	SharedLo    frontend.Variable
	SharedHi    frontend.Variable
}

func AgreeKey(api frontend.API, ephemeralSk, recipientPk [32]frontend.Variable) KeyAgreement {
	requireBN254(api)

	bits := scalarBits(api, ephemeralSk)
	ephemeral := scalarMulGenerator(api, bits)
	f := emfield.NewFor(api, prime(), defaultLayout)
	shared := ecdh(api, f, clampedScalarFromBits(api, f, bits), recipientPk)
	var result KeyAgreement
	result.RecipientLo, result.RecipientHi = packKeyBytes(api, recipientPk)
	result.EphemeralLo, result.EphemeralHi = packKeyBytes(api, ephemeral)
	result.SharedLo, result.SharedHi = packKeyBytes(api, shared)
	return result
}

func packKeyBytes(api frontend.API, encoded [32]frontend.Variable) (lo, hi frontend.Variable) {
	lo = frontend.Variable(0)
	for _, b := range encoded[:31] {
		lo = api.Add(api.Mul(lo, 256), b)
	}
	return lo, encoded[31]
}
