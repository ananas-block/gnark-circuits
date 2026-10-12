package main

import (
	"github.com/consensys/gnark/frontend"
)

// instance is one hash, signature verification or encryption with its own witness; a benchmark
// circuit holds one or more of them.
type instance interface {
	define(api frontend.API) error
}

type batch[T instance] struct {
	Instances []T
}

func (b *batch[T]) Define(api frontend.API) error {
	for _, inst := range b.Instances {
		if err := inst.define(api); err != nil {
			return err
		}
	}
	return nil
}

type row struct {
	section string
	name    string
	// circuits returns the blank circuit and a satisfying assignment of n
	// instances with distinct inputs.
	circuits func(n int) (frontend.Circuit, frontend.Circuit, error)
}

// rowOf builds a row from a constructor of instance i. The blank instance
// must not share slices with any other, since compilation writes a variable
// into every leaf.
func rowOf[T instance](section, name string, build func(i int) (blank, assigned T, err error)) row {
	return row{section: section, name: name, circuits: func(n int) (frontend.Circuit, frontend.Circuit, error) {
		blank := &batch[T]{Instances: make([]T, n)}
		assigned := &batch[T]{Instances: make([]T, n)}
		for i := 0; i < n; i++ {
			b, a, err := build(i)
			if err != nil {
				return nil, nil, err
			}
			blank.Instances[i], assigned.Instances[i] = b, a
		}
		return blank, assigned, nil
	}}
}

const (
	sectionHasher     = "Hasher"
	sectionEncryption = "Encryption"
	sectionP256       = "P-256"
	sectionEd25519    = "Ed25519"
)

func rows() []row {
	return []row{
		rowOf(sectionHasher, "SHA-512 lookup, 64 B message (one compression)", buildSha512(64)),
		rowOf(sectionHasher, "SHA-512 lookup, 128 B message (two compressions)", buildSha512(128)),
		rowOf(sectionEd25519, "Ed25519 verification + SHA-512, 32 B message (Solana)", buildEd25519(32)),
		rowOf(sectionP256, "P-256 ECDH (ECDH)", buildP256ECDH),
		rowOf(sectionP256, "P-256 key agreement (AgreeKey)", buildP256AgreeKey),
		rowOf(sectionP256, "P-256 ECDSA verification (VerifyECDSA)", buildP256ECDSA),
		rowOf(sectionP256, "P-256 ECDSA gnark std ecdsa IsValid (fake-GLV, unsound)", buildP256StdECDSA),
		rowOf(sectionEncryption, "AES-256-CTR spread lookup, 16 B (Cipher.CTREncrypt)", buildAESCtr(16)),
		rowOf(sectionEncryption, "AES-256-CTR spread lookup, 40 B (Cipher.CTREncrypt)", buildAESCtr(40)),
		rowOf(sectionEncryption, "AES-256-CTR spread lookup, 48 B (Cipher.CTREncrypt)", buildAESCtr(48)),
		rowOf(sectionEncryption, "ECIES envelope P-256 + Poseidon KDF + AES-256-CTR, 16 B (Envelope.Seal)", buildEciesEnvelope(16)),
		rowOf(sectionEncryption, "ECIES envelope P-256 + Poseidon KDF + AES-256-CTR, 40 B (Envelope.Seal)", buildEciesEnvelope(40)),
		rowOf(sectionEncryption, "ECIES envelope P-256 + Poseidon KDF + AES-256-CTR, 48 B (Envelope.Seal)", buildEciesEnvelope(48)),
	}
}

// inputBytes is the deterministic message of instance i; salt separates the
// key from the message of one instance.
func inputBytes(i, n, salt int) []byte {
	out := make([]byte, n)
	for k := range out {
		out[k] = byte(37*i + 7*k + salt + 3)
	}
	return out
}

func assertDigest(api frontend.API, digest, published []frontend.Variable) {
	for i := range digest {
		api.AssertIsEqual(published[i], digest[i])
	}
}

func fill(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = b
	}
}
