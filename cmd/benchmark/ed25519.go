package main

import (
	"crypto/ed25519"
	"crypto/sha512"

	"github.com/consensys/gnark/frontend"

	edgadget "github.com/ananas-block/gnark-circuits/ed25519"
	"github.com/ananas-block/gnark-circuits/hasher"
)

type ed25519Verify struct {
	PublicKey [32]frontend.Variable `gnark:",public"`
	Signature [64]frontend.Variable
	Message   []frontend.Variable `gnark:",public"`
}

func (v ed25519Verify) define(api frontend.API) error {
	edgadget.Verify(api, edgadget.Inputs{PublicKey: v.PublicKey, Signature: v.Signature, Message: v.Message})
	return nil
}
func buildEd25519(n int) func(int) (ed25519Verify, ed25519Verify, error) {
	return func(i int) (ed25519Verify, ed25519Verify, error) {
		sk := ed25519.NewKeyFromSeed(inputBytes(i, 32, 173))
		msg := inputBytes(i, n, 211)
		sig := ed25519.Sign(sk, msg)
		pk := sk.Public().(ed25519.PublicKey)
		blank := ed25519Verify{Message: make([]frontend.Variable, n)}
		w := ed25519Verify{Message: make([]frontend.Variable, n)}
		fill(w.PublicKey[:], pk)
		fill(w.Signature[:], sig)
		fill(w.Message, msg)
		return blank, w, nil
	}
}

type sha512Hash struct {
	Message []frontend.Variable
	Digest  [64]frontend.Variable `gnark:",public"`
}

func (v sha512Hash) define(api frontend.API) error {
	d := hasher.Sha512(api, v.Message)
	assertDigest(api, d[:], v.Digest[:])
	return nil
}
func buildSha512(n int) func(int) (sha512Hash, sha512Hash, error) {
	return func(i int) (sha512Hash, sha512Hash, error) {
		msg := inputBytes(i, n, 229)
		digest := sha512.Sum512(msg)
		blank := sha512Hash{Message: make([]frontend.Variable, n)}
		w := sha512Hash{Message: make([]frontend.Variable, n)}
		fill(w.Message, msg)
		fill(w.Digest[:], digest[:])
		return blank, w, nil
	}
}
