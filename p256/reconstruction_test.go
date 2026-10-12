package p256

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

func TestReconstructionHalvesFit128Bits(t *testing.T) {
	n := GroupOrder()
	root := new(big.Int).Sqrt(n)
	bound := pow2(halfScalarBits - 1)
	// The half-GCD invariant is r0*|t1|+r1*|t0|=n. Its stopping rule
	// gives r1<floor(sqrt(n)) and r0>=floor(sqrt(n)); hence
	// |t1|<=n/floor(sqrt(n)). This fixed-order inequality is strict.
	if new(big.Int).Mul(bound, root).Cmp(n) <= 0 {
		t.Fatal("P-256 denominator bound is not below 2^128")
	}
	values := []*big.Int{new(big.Int), big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1)), n, new(big.Int).Add(n, big.NewInt(1)), new(big.Int).Sub(root, big.NewInt(1)), root, new(big.Int).Add(root, big.NewInt(1)), new(big.Int).Sub(bound, big.NewInt(1)), bound, new(big.Int).Add(bound, big.NewInt(1))}
	rng := rand.New(rand.NewSource(128))
	for i := 0; i < 256; i++ {
		values = append(values, new(big.Int).Rand(rng, n))
	}
	rc := lattice.NewReconstructor(n)
	for _, s := range values {
		pair := rc.RationalReconstruct(s)
		if pair[0].Sign() < 0 || pair[0].Cmp(bound) >= 0 || new(big.Int).Abs(pair[1]).Cmp(bound) >= 0 || pair[1].Sign() == 0 {
			t.Fatalf("scalar %x: reconstruction exceeds 128-bit bounds", s)
		}
		if new(big.Int).Mod(new(big.Int).Sub(pair[0], new(big.Int).Mul(s, pair[1])), n).Sign() != 0 {
			t.Fatalf("scalar %x: reconstruction relation failed", s)
		}
	}
}

type radixHalfBoundCircuit struct {
	Bits [halfScalarBits]frontend.Variable
	Want frontend.Variable `gnark:",public"`
}

func (c *radixHalfBoundCircuit) Define(api frontend.API) error {
	curve := newCurve(api)
	digits := curve.radixFourDigits(c.Bits[:])
	scalar := curve.scalarFromRadixFour(c.Bits[0], digits)
	api.AssertIsEqual(curve.nativeValue(scalar), c.Want)
	return nil
}

func TestRadixHalfTopDigitIsBoundedToOneBit(t *testing.T) {
	cs := compile(t, &radixHalfBoundCircuit{})
	for _, row := range []struct {
		low, high int
		accept    bool
	}{{0, 0, true}, {1, 0, true}, {3, -1, true}, {2, 0, false}, {0, 1, false}} {
		w := &radixHalfBoundCircuit{}
		for i := range w.Bits {
			w.Bits[i] = 0
		}
		w.Bits[halfScalarBits-2], w.Bits[halfScalarBits-1] = row.low, row.high
		w.Want = new(big.Int).Mul(big.NewInt(int64(row.low+2*row.high)), pow2(halfScalarBits-2))
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err = cs.IsSolved(witness); (err == nil) != row.accept {
			t.Fatalf("top constituents %d,%d: accept=%v err=%v", row.low, row.high, row.accept, err)
		}
	}
}
