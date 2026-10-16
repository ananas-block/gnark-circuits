package encryption

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

func mustPoseidon(t testing.TB, inputs ...*big.Int) *big.Int {
	t.Helper()
	h, err := poseidon.Hash(inputs)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func hostKeySchedule(t testing.TB, sharedSecret *big.Int, info []byte) (key []byte, nonce []byte) {
	t.Helper()
	inputs := []*big.Int{new(big.Int).SetUint64(uint64(DomSepSilo)), sharedSecret}
	for start := 0; start < len(info); start += 31 {
		inputs = append(inputs, new(big.Int).SetBytes(info[start:min(start+31, len(info))]))
	}
	silo := mustPoseidon(t, inputs...)
	lo := mustPoseidon(t, new(big.Int).SetUint64(uint64(DomSepKey)), silo).FillBytes(make([]byte, 32))
	hi := mustPoseidon(t, new(big.Int).SetUint64(uint64(DomSepKeyHi)), silo).FillBytes(make([]byte, 32))
	n := mustPoseidon(t, new(big.Int).SetUint64(uint64(DomSepNonce)), silo).FillBytes(make([]byte, 32))
	key = append(append([]byte{}, hi[16:]...), lo[16:]...)
	nonce = append([]byte{}, n[20:]...)
	return key, nonce
}

func compileAndCheck(t *testing.T, circuit, assignment frontend.Circuit, opts ...solver.Option) error {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return cs.IsSolved(w, opts...)
}

type keyScheduleCircuit struct {
	Secret frontend.Variable
	Key    [KeyBytes]frontend.Variable   `gnark:",public"`
	Nonce  [NonceBytes]frontend.Variable `gnark:",public"`
	info   []byte
}

func (c *keyScheduleCircuit) Define(api frontend.API) error {
	key, nonce := KeySchedule(api, c.Secret, c.info)
	for i, b := range key {
		api.AssertIsEqual(b, c.Key[i])
	}
	for i, b := range nonce {
		api.AssertIsEqual(b, c.Nonce[i])
	}
	return nil
}

func TestKeyScheduleMatchesHostAtBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 30, 31, 32, 62, 63, 434} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			info := bytes.Repeat([]byte{0xa5}, size)

			if size > 31 {
				info[0] = 0
			}
			circuit := &keyScheduleCircuit{info: info}
			for _, secret := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))} {
				key, nonce := hostKeySchedule(t, secret, info)
				w := &keyScheduleCircuit{Secret: secret}
				for i, b := range key {
					w.Key[i] = b
				}
				for i, b := range nonce {
					w.Nonce[i] = b
				}
				if err := compileAndCheck(t, circuit, w); err != nil {
					t.Fatal(err)
				}
				w.Key[0] = key[0] ^ 1
				if compileAndCheck(t, circuit, w) == nil {
					t.Fatal("a wrong key byte was accepted")
				}
				w.Key[0] = key[0]
				w.Nonce[11] = nonce[11] ^ 1
				if compileAndCheck(t, circuit, w) == nil {
					t.Fatal("a wrong nonce byte was accepted")
				}
			}
		})
	}
}

func TestKeyScheduleRejectsAmbiguousInfo(t *testing.T) {
	for _, prefixChunks := range []int{0, 1, 13} {
		for _, tailSize := range []int{1, 2, 30, 31} {
			t.Run(fmt.Sprintf("prefix_%d_tail_%d", prefixChunks, tailSize), func(t *testing.T) {
				info := bytes.Repeat([]byte{0xa5}, 31*prefixChunks+tailSize)
				info[31*prefixChunks] = 0
				_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &keyScheduleCircuit{info: info})
				if err == nil || !strings.Contains(err.Error(), "kdf: final info chunk must not start with zero") {
					t.Fatalf("want ambiguous info rejected at compilation, got %v", err)
				}
			})
		}
	}
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &keyScheduleCircuit{info: bytes.Repeat([]byte{1}, 435)})
	if err == nil || !strings.Contains(err.Error(), "kdf: info of 435 bytes, at most 434") {
		t.Fatalf("want oversized info rejected at compilation, got %v", err)
	}
}

func TestKeyScheduleConstraintCount(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &keyScheduleCircuit{info: MergeKdfInfo})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("KeySchedule over %d info bytes: %d constraints", len(MergeKdfInfo), cs.GetNbConstraints())
}
