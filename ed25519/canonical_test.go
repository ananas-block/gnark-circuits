package ed25519

import (
	"errors"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type canonicalPointCircuit struct{ Encoding [32]frontend.Variable }

func (v *canonicalPointCircuit) Define(api frontend.API) error {
	c := newCurve(api)
	p := c.decodeEncoding(v.Encoding)
	_, torsion := c.splitTorsion(p)
	c.assertCanonicalPrime(p, torsion)
	return nil
}

func encodeTestPoint(p hostPoint) (out [32]frontend.Variable) {
	for i := range out {
		out[i] = byte(new(big.Int).Rsh(p.y, uint(8*i)).Uint64())
	}
	out[31] = out[31].(byte) | byte(p.x.Bit(0))<<7
	return out
}

func TestCanonicalPointPolicyRejectsTorsionAndAliases(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalPointCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, p [32]frontend.Variable, want bool, opts ...solver.Option) {
		t.Helper()
		w, err := frontend.NewWitness(&canonicalPointCircuit{Encoding: p}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(w, opts...)
		if !want {
			requireConstraintRejection(t, err)
		} else if err != nil {
			t.Fatal(err)
		}
	}
	check(t, encodeTestPoint(generator()), true)
	for i, torsion := range torsionTable() {
		t.Run("small-order/"+big.NewInt(int64(i)).String(), func(t *testing.T) { check(t, encodeTestPoint(torsion), false) })
		if i != 0 {
			t.Run("mixed-torsion/"+big.NewInt(int64(i)).String(), func(t *testing.T) {
				encoded := encodeTestPoint(hostAdd(generator(), torsion))
				check(t, encoded, false)
				called := false
				forge := func(_ *big.Int, _, out []*big.Int) error { called = true; out[0].SetInt64(0); return nil }
				check(t, encoded, false, solver.OverrideHint(solver.GetHintID(torsionIndexHint), forge))
				if !called {
					t.Fatal("torsion hint was not exercised")
				}
			})
		}
	}
	for i := int64(0); i < 19; i++ {
		called := false
		zeroSplit := func(_ *big.Int, _, out []*big.Int) error { called = true; out[0].SetInt64(0); return nil }
		check(t, encodeTestPoint(hostPoint{new(big.Int), new(big.Int).Add(Prime(), big.NewInt(i))}), false, solver.OverrideHint(solver.GetHintID(torsionIndexHint), zeroSplit))
		if !called {
			t.Fatal("malformed-point hint override was not exercised")
		}
	}
	negativeZero := encodeTestPoint(hostPoint{new(big.Int), big.NewInt(1)})
	negativeZero[31] = byte(128)
	check(t, negativeZero, false)
}

type canonicalCoreCircuit coreCircuit

func (v *canonicalCoreCircuit) Define(api frontend.API) error {
	verifyDigest(api, v.PublicKey, v.Signature, v.Digest)
	return nil
}

// These witnesses satisfy the group equation with deliberately cancelling
// torsion. Rejecting them proves the policy is stronger than the equation.
func TestCanonicalSignatureRejectsCancellingTorsion(t *testing.T) {
	strict, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalCoreCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &coreCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for i, torsion := range torsionTable() {
		w := &canonicalCoreCircuit{}
		for j := range w.Signature {
			w.Signature[j] = 0
		}
		for j := range w.Digest {
			w.Digest[j] = 0
		}
		w.PublicKey = encodeTestPoint(hostAdd(hostMul(generator(), big.NewInt(5)), torsion))
		r := hostAdd(hostMul(generator(), big.NewInt(7)), hostNeg(hostMul(torsion, big.NewInt(3))))
		encodedR := encodeTestPoint(r)
		copy(w.Signature[:32], encodedR[:])
		w.Signature[32], w.Digest[0] = 22, 3
		wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := reference.IsSolved(wit); err != nil {
			t.Fatalf("valid reference equation %d: %v", i, err)
		}
		if accepted := strict.IsSolved(wit) == nil; accepted != (i == 0) {
			t.Fatalf("torsion %d accepted=%v", i, accepted)
		}
	}
}

// Require an actual failed constraint, rather than a hint refusing the witness.
func requireConstraintRejection(t testing.TB, err error) {
	t.Helper()
	var unsatisfied *cs_bn254.UnsatisfiedConstraintError
	if !errors.As(err, &unsatisfied) {
		t.Fatalf("expected constraint rejection, got %v", err)
	}
	if unsatisfied.Err == nil || !strings.Contains(unsatisfied.Err.Error(), " ⋅ ") || !strings.Contains(unsatisfied.Err.Error(), " != ") {
		t.Fatalf("stopped outside a constraint equation: %v", err)
	}
}

// Isolate the y bound from subgroup rejection: none of the small y aliases
// in the point-policy corpus needs to be a nonidentity prime-subgroup point.
type canonicalYBoundCircuit struct{ Y [32]frontend.Variable }

func (v *canonicalYBoundCircuit) Define(api frontend.API) error {
	c := newCurve(api)
	c.assertCanonicalPrime(&point{x: c.one, y: c.byteElement(c.fp, v.Y[:], 255)}, 0)
	return nil
}

func TestCanonicalYBound(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalYBoundCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int64{-1, 0, 18} {
		y := new(big.Int).Add(Prime(), big.NewInt(offset))
		w := &canonicalYBoundCircuit{Y: encodeTestPoint(hostPoint{new(big.Int), y})}
		wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if accepted := cs.IsSolved(wit) == nil; accepted != (offset < 0) {
			t.Fatalf("y=p%+d accepted=%v", offset, accepted)
		}
	}
}
