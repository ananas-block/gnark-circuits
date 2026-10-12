package p256

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
)

func TestAgreeKeyRadixFourDigitBounds(t *testing.T) {
	cs := compile(t, &agreeKeyCircuit{})
	honest := agreeKeyWitness(t, mergeScalar, peerKey(t).PublicKey())
	for _, row := range []struct {
		name   string
		change func(q *big.Int, outputs []*big.Int)
		accept bool
	}{
		{
			"same digit with non-Boolean constituents",
			func(q *big.Int, outputs []*big.Int) {
				// The circuit consumes b1 + 2b2, so this preserves the digit.
				outputs[2].Add(outputs[2], big.NewInt(2)).Mod(outputs[2], q)
				outputs[3].Sub(outputs[3], big.NewInt(1)).Mod(outputs[3], q)
			}, true,
		},
		{
			"same top digit with non-Boolean constituents",
			func(q *big.Int, outputs []*big.Int) {
				outputs[halfScalarBits-1].Add(outputs[halfScalarBits-1], big.NewInt(2)).Mod(outputs[halfScalarBits-1], q)
				outputs[halfScalarBits].Sub(outputs[halfScalarBits], big.NewInt(1)).Mod(outputs[halfScalarBits], q)
			}, true,
		},
		{
			"radix carry preserves scalar but exceeds digit bound",
			func(q *big.Int, outputs []*big.Int) {
				// Adding 4 to d0 and subtracting 1 from d1 leaves the scalar
				// unchanged. It must still fail the independent digit range.
				outputs[2].Add(outputs[2], big.NewInt(4)).Mod(outputs[2], q)
				outputs[4].Sub(outputs[4], big.NewInt(1)).Mod(outputs[4], q)
			}, false,
		},
		{
			"low bit carry preserves scalar but exceeds Boolean bound",
			func(q *big.Int, outputs []*big.Int) {
				outputs[1].Add(outputs[1], big.NewInt(2)).Mod(outputs[1], q)
				outputs[2].Sub(outputs[2], big.NewInt(1)).Mod(outputs[2], q)
			}, false,
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			called := false
			override := solver.OverrideHint(solver.GetHintID(p256DecomposeScalarHint), func(q *big.Int, inputs, outputs []*big.Int) error {
				called = true
				if err := p256DecomposeScalarHint(q, inputs, outputs); err != nil {
					return err
				}
				row.change(q, outputs)
				return nil
			})
			err := solveAgreeKey(t, cs, honest, override)
			if !called {
				t.Fatal("decomposition override did not run")
			}
			if (err == nil) != row.accept {
				t.Fatalf("accept=%v: %v", row.accept, err)
			}
		})
	}
}
