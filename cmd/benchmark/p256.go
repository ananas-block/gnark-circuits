package main

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	stdecdsa "github.com/consensys/gnark/std/signature/ecdsa"

	"github.com/ananas-block/gnark-circuits/p256"
)

type p256Key struct {
	scalar *big.Int
	x, y   *big.Int
}

func p256KeyOf(i, salt int) (p256Key, error) {
	n := elliptic.P256().Params().N
	scalar := new(big.Int).SetBytes(inputBytes(i, 32, salt))
	scalar.Mod(scalar, new(big.Int).Sub(n, big.NewInt(1))).Add(scalar, big.NewInt(2))
	key, err := ecdh.P256().NewPrivateKey(scalar.FillBytes(make([]byte, 32)))
	if err != nil {
		return p256Key{}, err
	}
	point := key.PublicKey().Bytes()
	return p256Key{scalar: scalar, x: new(big.Int).SetBytes(point[1:33]), y: new(big.Int).SetBytes(point[33:65])}, nil
}

func (k p256Key) uncompressed() []byte {
	out := make([]byte, 65)
	out[0] = 0x04
	k.x.FillBytes(out[1:33])
	k.y.FillBytes(out[33:65])
	return out
}

type p256Pair struct {
	ephemeral, recipient p256Key
	shared               []byte
}

func p256PairOf(i int) (p256Pair, error) {
	ephemeral, err := p256KeyOf(i, 11)
	if err != nil {
		return p256Pair{}, err
	}
	recipient, err := p256KeyOf(i, 29)
	if err != nil {
		return p256Pair{}, err
	}
	sk, err := ecdh.P256().NewPrivateKey(ephemeral.scalar.FillBytes(make([]byte, 32)))
	if err != nil {
		return p256Pair{}, err
	}
	pk, err := ecdh.P256().NewPublicKey(recipient.uncompressed())
	if err != nil {
		return p256Pair{}, err
	}
	shared, err := sk.ECDH(pk)
	if err != nil {
		return p256Pair{}, err
	}
	return p256Pair{ephemeral: ephemeral, recipient: recipient, shared: shared}, nil
}

type p256ECDH struct {
	Scalar    [32]frontend.Variable
	PublicKey [65]frontend.Variable
	Shared    [32]frontend.Variable `gnark:",public"`
}

func (c p256ECDH) define(api frontend.API) error {
	got := p256.ECDH(api, c.Scalar, c.PublicKey)
	assertDigest(api, got[:], c.Shared[:])
	return nil
}

func buildP256ECDH(i int) (p256ECDH, p256ECDH, error) {
	pair, err := p256PairOf(i)
	if err != nil {
		return p256ECDH{}, p256ECDH{}, err
	}
	var w p256ECDH
	fill(w.Scalar[:], pair.ephemeral.scalar.FillBytes(make([]byte, 32)))
	fill(w.PublicKey[:], pair.recipient.uncompressed())
	fill(w.Shared[:], pair.shared)
	return p256ECDH{}, w, nil
}

type p256AgreeKey struct {
	Scalar    [32]frontend.Variable
	PublicKey [65]frontend.Variable
	Expected  [6]frontend.Variable `gnark:",public"`
}

func (c p256AgreeKey) define(api frontend.API) error {
	got := p256.AgreeKey(api, c.Scalar, c.PublicKey)
	assertDigest(api, []frontend.Variable{got.RecipientLo, got.RecipientHi, got.EphemeralLo, got.EphemeralHi, got.SharedLo, got.SharedHi}, c.Expected[:])
	return nil
}

func splitLoHi(bytes []byte) (*big.Int, *big.Int) {
	return new(big.Int).SetBytes(bytes[:31]), new(big.Int).SetBytes(bytes[31:])
}

func compressedKey(k p256Key) []byte {
	return append([]byte{byte(2 + k.y.Bit(0))}, k.x.FillBytes(make([]byte, 32))...)
}

func buildP256AgreeKey(i int) (p256AgreeKey, p256AgreeKey, error) {
	pair, err := p256PairOf(i)
	if err != nil {
		return p256AgreeKey{}, p256AgreeKey{}, err
	}
	var w p256AgreeKey
	fill(w.Scalar[:], pair.ephemeral.scalar.FillBytes(make([]byte, 32)))
	fill(w.PublicKey[:], pair.recipient.uncompressed())
	for k, part := range [][]byte{compressedKey(pair.recipient), compressedKey(pair.ephemeral), pair.shared} {
		w.Expected[2*k], w.Expected[2*k+1] = splitLoHi(part)
	}
	return p256AgreeKey{}, w, nil
}

type p256Signature struct {
	key     p256Key
	h, r, s *big.Int
}

func p256SignatureOf(i int) (p256Signature, error) {
	return p256SignatureForMessage(i, inputBytes(i, 64, 67))
}

func p256SignatureForMessage(i int, message []byte) (p256Signature, error) {
	n := elliptic.P256().Params().N
	key, err := p256KeyOf(i, 41)
	if err != nil {
		return p256Signature{}, err
	}
	nonce, err := p256KeyOf(i, 53)
	if err != nil {
		return p256Signature{}, err
	}
	digest := sha256.Sum256(message)
	h := new(big.Int).SetBytes(digest[:])
	r := new(big.Int).Mod(nonce.x, n)
	s := new(big.Int).Mul(r, key.scalar)
	s.Add(s, h).Mul(s, new(big.Int).ModInverse(nonce.scalar, n)).Mod(s, n)
	if r.Sign() == 0 || s.Sign() == 0 {
		return p256Signature{}, fmt.Errorf("degenerate signature for instance %d", i)
	}
	return p256Signature{key: key, h: h, r: r, s: s}, nil
}

func limbs64(v *big.Int) [4]frontend.Variable {
	var out [4]frontend.Variable
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	for i := range out {
		out[i] = new(big.Int).And(new(big.Int).Rsh(v, uint(64*i)), mask)
	}
	return out
}

type p256ECDSA struct {
	PublicKeyX [4]frontend.Variable
	PublicKeyY [4]frontend.Variable
	R          [4]frontend.Variable
	S          [4]frontend.Variable
	Message    [4]frontend.Variable
	Identity   [32]frontend.Variable `gnark:",public"`
}

func (c p256ECDSA) define(api frontend.API) error {
	got := p256.VerifyECDSA(api, p256.ECDSAInputs{
		LimbBits:   64,
		PublicKeyX: c.PublicKeyX[:],
		PublicKeyY: c.PublicKeyY[:],
		R:          c.R[:],
		S:          c.S[:],
		Message:    c.Message[:],
	})
	assertDigest(api, got[:], c.Identity[:])
	return nil
}

func buildP256ECDSA(i int) (p256ECDSA, p256ECDSA, error) {
	sig, err := p256SignatureOf(i)
	if err != nil {
		return p256ECDSA{}, p256ECDSA{}, err
	}
	w := p256ECDSA{
		PublicKeyX: limbs64(sig.key.x),
		PublicKeyY: limbs64(sig.key.y),
		R:          limbs64(sig.r),
		S:          limbs64(sig.s),
		Message:    limbs64(sig.h),
	}
	fill(w.Identity[:], sig.key.x.FillBytes(make([]byte, 32)))
	return p256ECDSA{}, w, nil
}

type p256StdECDSA struct {
	PublicKey stdecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr] `gnark:",public"`
	Signature stdecdsa.Signature[emulated.P256Fr]
	Message   emulated.Element[emulated.P256Fr]
}

func (c p256StdECDSA) define(api frontend.API) error {
	api.AssertIsEqual(c.PublicKey.IsValid(api, sw_emulated.GetP256Params(), &c.Message, &c.Signature), 1)
	return nil
}

func buildP256StdECDSA(i int) (p256StdECDSA, p256StdECDSA, error) {
	sig, err := p256SignatureOf(i)
	if err != nil {
		return p256StdECDSA{}, p256StdECDSA{}, err
	}
	return p256StdECDSA{}, p256StdECDSA{
		PublicKey: stdecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](sig.key.x),
			Y: emulated.ValueOf[emulated.P256Fp](sig.key.y),
		},
		Signature: stdecdsa.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](sig.r),
			S: emulated.ValueOf[emulated.P256Fr](sig.s),
		},
		Message: emulated.ValueOf[emulated.P256Fr](new(big.Int).Mod(sig.h, elliptic.P256().Params().N)),
	}, nil
}
