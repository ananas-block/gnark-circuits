package main

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/iden3/go-iden3-crypto/poseidon"

	"github.com/ananas-block/gnark-circuits/encryption"
	"github.com/ananas-block/gnark-circuits/encryption/aes"
)

type aesCtr struct {
	Key        [32]frontend.Variable
	Nonce      [12]frontend.Variable `gnark:",public"`
	Plaintext  []frontend.Variable
	Ciphertext []frontend.Variable `gnark:",public"`
}

func (c aesCtr) define(api frontend.API) error {
	ciphertext := aes.NewCipher(api, c.Key).CTREncrypt(c.Nonce, c.Plaintext)
	assertDigest(api, ciphertext, c.Ciphertext)
	return nil
}

func hostAESCtr(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := stdaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := append(append([]byte{}, nonce...), 0, 0, 0, 2)
	out := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(out, plaintext)
	return out, nil
}

func buildAESCtr(n int) func(i int) (aesCtr, aesCtr, error) {
	return func(i int) (aesCtr, aesCtr, error) {
		key, nonce, plaintext := inputBytes(i, 32, 101), inputBytes(i, 12, 211), inputBytes(i, n, 0)
		ciphertext, err := hostAESCtr(key, nonce, plaintext)
		if err != nil {
			return aesCtr{}, aesCtr{}, err
		}
		w := aesCtr{Plaintext: make([]frontend.Variable, n), Ciphertext: make([]frontend.Variable, n)}
		fill(w.Key[:], key)
		fill(w.Nonce[:], nonce)
		fill(w.Plaintext, plaintext)
		fill(w.Ciphertext, ciphertext)
		return aesCtr{Plaintext: make([]frontend.Variable, n), Ciphertext: make([]frontend.Variable, n)}, w, nil
	}
}

type eciesEnvelope struct {
	EphemeralSk [32]frontend.Variable
	RecipientPk [65]frontend.Variable
	Plaintext   []frontend.Variable
	Packed      [4]frontend.Variable `gnark:",public"`
	Ciphertext  []frontend.Variable  `gnark:",public"`
}

func (c eciesEnvelope) define(api frontend.API) error {
	sealed := encryption.Envelope{
		SecretTag:   encryption.MergeSecretTag,
		KdfInfo:     encryption.MergeKdfInfo,
		EphemeralSk: c.EphemeralSk,
		RecipientPk: c.RecipientPk,
		Plaintext:   c.Plaintext,
	}.Seal(api)
	assertDigest(api, []frontend.Variable{sealed.RecipientLo, sealed.RecipientHi, sealed.EphemeralLo, sealed.EphemeralHi}, c.Packed[:])
	assertDigest(api, sealed.Ciphertext, c.Ciphertext)
	return nil
}

// hostKeySchedule mirrors encryption.KeySchedule, Zolana's key schedule.
func hostKeySchedule(sharedSecret *big.Int, info []byte) ([]byte, []byte, error) {
	inputs := []*big.Int{new(big.Int).SetUint64(uint64(encryption.DomSepSilo)), sharedSecret}
	for start := 0; start < len(info); start += 31 {
		inputs = append(inputs, new(big.Int).SetBytes(info[start:min(start+31, len(info))]))
	}
	silo, err := poseidon.Hash(inputs)
	if err != nil {
		return nil, nil, err
	}
	derive := func(tag uint32) ([]byte, error) {
		h, err := poseidon.Hash([]*big.Int{new(big.Int).SetUint64(uint64(tag)), silo})
		if err != nil {
			return nil, err
		}
		return h.FillBytes(make([]byte, 32)), nil
	}
	lo, err := derive(encryption.DomSepKey)
	if err != nil {
		return nil, nil, err
	}
	hi, err := derive(encryption.DomSepKeyHi)
	if err != nil {
		return nil, nil, err
	}
	n, err := derive(encryption.DomSepNonce)
	if err != nil {
		return nil, nil, err
	}
	return append(append([]byte{}, hi[16:]...), lo[16:]...), append([]byte{}, n[20:]...), nil
}

func buildEciesEnvelope(n int) func(i int) (eciesEnvelope, eciesEnvelope, error) {
	return func(i int) (eciesEnvelope, eciesEnvelope, error) {
		blank := eciesEnvelope{Plaintext: make([]frontend.Variable, n), Ciphertext: make([]frontend.Variable, n)}
		pair, err := p256PairOf(i)
		if err != nil {
			return eciesEnvelope{}, eciesEnvelope{}, err
		}
		recipientLo, recipientHi := splitLoHi(compressedKey(pair.recipient))
		ephemeralLo, ephemeralHi := splitLoHi(compressedKey(pair.ephemeral))
		sharedLo, sharedHi := splitLoHi(pair.shared)
		secret, err := poseidon.Hash([]*big.Int{
			encryption.SecretTagValue(encryption.MergeSecretTag),
			sharedLo, sharedHi, ephemeralLo, ephemeralHi, recipientLo, recipientHi,
		})
		if err != nil {
			return eciesEnvelope{}, eciesEnvelope{}, err
		}
		key, nonce, err := hostKeySchedule(secret, encryption.MergeKdfInfo)
		if err != nil {
			return eciesEnvelope{}, eciesEnvelope{}, err
		}
		plaintext := inputBytes(i, n, 0)
		ciphertext, err := hostAESCtr(key, nonce, plaintext)
		if err != nil {
			return eciesEnvelope{}, eciesEnvelope{}, err
		}
		w := eciesEnvelope{Plaintext: make([]frontend.Variable, n), Ciphertext: make([]frontend.Variable, n)}
		fill(w.EphemeralSk[:], pair.ephemeral.scalar.FillBytes(make([]byte, 32)))
		fill(w.RecipientPk[:], pair.recipient.uncompressed())
		w.Packed = [4]frontend.Variable{recipientLo, recipientHi, ephemeralLo, ephemeralHi}
		fill(w.Plaintext, plaintext)
		fill(w.Ciphertext, ciphertext)
		return blank, w, nil
	}
}
