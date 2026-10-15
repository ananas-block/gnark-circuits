package encryption

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

const eciesPlaintextBytes = 40

type eciesHostKeys struct {
	recipientPublicKey [32]byte
	ephemeralScalar    [32]byte
	recipientLo        *big.Int
	recipientHi        *big.Int
	ephemeralLo        *big.Int
	ephemeralHi        *big.Int
	sharedSecret       *big.Int
}

func packBytes32(bytes []byte) (*big.Int, *big.Int) {
	return new(big.Int).SetBytes(bytes[:31]), new(big.Int).SetBytes(bytes[31:32])
}

func newEciesHostKeys(t testing.TB) eciesHostKeys {
	t.Helper()
	curve := ecdh.X25519()
	recipientScalar := make([]byte, 32)
	recipientScalar[31] = 0x2b
	ephemeralScalar := make([]byte, 32)
	ephemeralScalar[0] = 0x0f
	ephemeralScalar[31] = 0x61
	recipientSk, err := curve.NewPrivateKey(recipientScalar)
	if err != nil {
		t.Fatal(err)
	}
	ephemeralSk, err := curve.NewPrivateKey(ephemeralScalar)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := ephemeralSk.ECDH(recipientSk.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	var keys eciesHostKeys
	copy(keys.ephemeralScalar[:], ephemeralScalar)
	copy(keys.recipientPublicKey[:], recipientSk.PublicKey().Bytes())
	keys.recipientLo, keys.recipientHi = packBytes32(recipientSk.PublicKey().Bytes())
	keys.ephemeralLo, keys.ephemeralHi = packBytes32(ephemeralSk.PublicKey().Bytes())
	dhLo, dhHi := packBytes32(dh)
	keys.sharedSecret = mustPoseidon(t,
		SecretTagValue(MergeSecretTag),
		dhLo, dhHi,
		keys.ephemeralLo, keys.ephemeralHi,
		keys.recipientLo, keys.recipientHi,
	)
	return keys
}

func hostAESCtr(t testing.TB, key, nonce, plaintext []byte) []byte {
	t.Helper()
	block, err := stdaes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := append(append([]byte{}, nonce...), 0, 0, 0, 2)
	out := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(out, plaintext)
	return out
}

type envelopeCircuit struct {
	EphemeralSk [ScalarBytes]frontend.Variable
	RecipientPk [PublicKeyBytes]frontend.Variable
	Plaintext   [eciesPlaintextBytes]frontend.Variable
	RecipientLo frontend.Variable                      `gnark:",public"`
	RecipientHi frontend.Variable                      `gnark:",public"`
	EphemeralLo frontend.Variable                      `gnark:",public"`
	EphemeralHi frontend.Variable                      `gnark:",public"`
	Ciphertext  [eciesPlaintextBytes]frontend.Variable `gnark:",public"`
}

func (c *envelopeCircuit) Define(api frontend.API) error {
	sealed := Envelope{
		SecretTag:   MergeSecretTag,
		KdfInfo:     MergeKdfInfo,
		EphemeralSk: c.EphemeralSk,
		RecipientPk: c.RecipientPk,
		Plaintext:   c.Plaintext[:],
	}.Seal(api)
	api.AssertIsEqual(sealed.RecipientLo, c.RecipientLo)
	api.AssertIsEqual(sealed.RecipientHi, c.RecipientHi)
	api.AssertIsEqual(sealed.EphemeralLo, c.EphemeralLo)
	api.AssertIsEqual(sealed.EphemeralHi, c.EphemeralHi)
	for i, b := range sealed.Ciphertext {
		api.AssertIsEqual(b, c.Ciphertext[i])
	}
	return nil
}

func envelopeAssignment(t testing.TB) *envelopeCircuit {
	t.Helper()
	keys := newEciesHostKeys(t)
	plaintext := make([]byte, eciesPlaintextBytes)
	for i := range plaintext {
		plaintext[i] = byte(31*i + 5)
	}
	key, nonce := hostKeySchedule(t, keys.sharedSecret, MergeKdfInfo)
	ciphertext := hostAESCtr(t, key, nonce, plaintext)
	a := &envelopeCircuit{
		RecipientLo: keys.recipientLo,
		RecipientHi: keys.recipientHi,
		EphemeralLo: keys.ephemeralLo,
		EphemeralHi: keys.ephemeralHi,
	}
	for i, b := range keys.ephemeralScalar {
		a.EphemeralSk[i] = b
	}
	for i, b := range keys.recipientPublicKey {
		a.RecipientPk[i] = b
	}
	for i := range plaintext {
		a.Plaintext[i] = plaintext[i]
		a.Ciphertext[i] = ciphertext[i]
	}
	return a
}

func TestEnvelopeMatchesHost(t *testing.T) {
	circuit := &envelopeCircuit{}
	if err := test.IsSolved(circuit, envelopeAssignment(t), ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("test engine: %v", err)
	}
	if err := compileAndCheck(t, circuit, envelopeAssignment(t)); err != nil {
		t.Fatalf("compiled R1CS: %v", err)
	}
}

func TestEnvelopeRejectsTamperedCiphertext(t *testing.T) {
	a := envelopeAssignment(t)
	a.Ciphertext[eciesPlaintextBytes-1] = a.Ciphertext[eciesPlaintextBytes-1].(byte) ^ 1
	if err := test.IsSolved(&envelopeCircuit{}, a, ecc.BN254.ScalarField()); err == nil {
		t.Fatalf("a tampered ciphertext was accepted")
	}
}

func TestEnvelopeRejectsForeignRecipient(t *testing.T) {
	other, err := ecdh.X25519().NewPrivateKey(append(make([]byte, 31), 0x2c))
	if err != nil {
		t.Fatal(err)
	}
	a := envelopeAssignment(t)
	for i, b := range other.PublicKey().Bytes() {
		a.RecipientPk[i] = b
	}
	if err := test.IsSolved(&envelopeCircuit{}, a, ecc.BN254.ScalarField()); err == nil {
		t.Fatalf("a foreign recipient key was accepted")
	}
}

func TestEnvelopeCommitmentCount(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &envelopeCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	got := len(cs.GetCommitments().CommitmentIndexes())
	t.Logf("envelope over %d bytes: %d constraints, %d BSB22 commitments", eciesPlaintextBytes, cs.GetNbConstraints(), got)
	if got != 1 {
		t.Fatalf("the envelope has %d BSB22 commitments, want one", got)
	}
	assertSinglePrivateCommitment(t, cs)
}
