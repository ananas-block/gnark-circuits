package x25519

import (
	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/internal/emfield"
)

// KeyAgreement binds the recipient encoding, derived ephemeral public key,
// and shared secret. Each Lo field is the first 31 encoded bytes interpreted
// as a big-endian integer; each Hi field is the final byte. The X25519
// coordinate encoding itself remains little endian.
type KeyAgreement struct {
	RecipientLo frontend.Variable
	RecipientHi frontend.Variable
	EphemeralLo frontend.Variable
	EphemeralHi frontend.Variable
	SharedLo    frontend.Variable
	SharedHi    frontend.Variable
}

// AgreeKey computes X25519 ECDH and the ephemeral public key from the same
// scalar. Recipient fields preserve all original input bytes, including the
// ignored high bit and noncanonical aliases; ECDH decodes them per RFC 7748.
// Ephemeral and shared encodings are canonical. All-zero shared secrets are
// rejected, and all input elements are constrained to bytes.
func AgreeKey(api frontend.API, ephemeralSk, recipientPk [32]frontend.Variable) KeyAgreement {
	requireBN254(api)
	// One bit decomposition serves both multiplications.
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
