package main

import (
	"crypto/ecdh"
	"math/big"

	"github.com/ananas-block/gnark-circuits/x25519"
	"github.com/consensys/gnark/frontend"
)

type x25519ECDH struct {
	Scalar    [32]frontend.Variable
	PublicKey [32]frontend.Variable
	Shared    [32]frontend.Variable `gnark:",public"`
}

func (c x25519ECDH) define(api frontend.API) error {
	got := x25519.ECDH(api, c.Scalar, c.PublicKey)
	assertDigest(api, got[:], c.Shared[:])
	return nil
}

func buildX25519ECDH() func(int) (x25519ECDH, x25519ECDH, error) {
	return func(i int) (x25519ECDH, x25519ECDH, error) {
		blank := x25519ECDH{}
		scalar := inputBytes(i, 32, 11)
		sk, err := ecdh.X25519().NewPrivateKey(scalar)
		if err != nil {
			return blank, blank, err
		}
		peer, err := ecdh.X25519().NewPrivateKey(inputBytes(i, 32, 29))
		if err != nil {
			return blank, blank, err
		}
		shared, err := sk.ECDH(peer.PublicKey())
		if err != nil {
			return blank, blank, err
		}
		w := blank
		fill(w.Scalar[:], scalar)
		fill(w.PublicKey[:], peer.PublicKey().Bytes())
		fill(w.Shared[:], shared)
		return blank, w, nil
	}
}

type x25519AgreeKey struct {
	Scalar    [32]frontend.Variable
	PublicKey [32]frontend.Variable
	Expected  [6]frontend.Variable `gnark:",public"`
}

func (c x25519AgreeKey) define(api frontend.API) error {
	got := x25519.AgreeKey(api, c.Scalar, c.PublicKey)
	assertDigest(api, []frontend.Variable{got.RecipientLo, got.RecipientHi, got.EphemeralLo, got.EphemeralHi, got.SharedLo, got.SharedHi}, c.Expected[:])
	return nil
}

func buildX25519AgreeKey() func(int) (x25519AgreeKey, x25519AgreeKey, error) {
	return func(i int) (x25519AgreeKey, x25519AgreeKey, error) {
		blank := x25519AgreeKey{}
		scalar := inputBytes(i, 32, 11)
		sk, err := ecdh.X25519().NewPrivateKey(scalar)
		if err != nil {
			return blank, blank, err
		}
		peer, err := ecdh.X25519().NewPrivateKey(inputBytes(i, 32, 29))
		if err != nil {
			return blank, blank, err
		}
		shared, err := sk.ECDH(peer.PublicKey())
		if err != nil {
			return blank, blank, err
		}
		w := blank
		fill(w.Scalar[:], scalar)
		fill(w.PublicKey[:], peer.PublicKey().Bytes())
		for j, encoded := range [][]byte{peer.PublicKey().Bytes(), sk.PublicKey().Bytes(), shared} {
			w.Expected[2*j], w.Expected[2*j+1] = splitLoHi(encoded)
		}
		return blank, w, nil
	}
}

func splitLoHi(encoded []byte) (*big.Int, *big.Int) {
	return new(big.Int).SetBytes(encoded[:31]), new(big.Int).SetBytes(encoded[31:])
}
