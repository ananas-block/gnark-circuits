package p256

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type combSelectCircuit struct {
	Window int `gnark:"-"`
	Bits   []frontend.Variable
	X, Y   [8]frontend.Variable
}

func (c *combSelectCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	for _, bit := range c.Bits {
		api.AssertIsBoolean(bit)
	}
	// An ordinary window permits sign folding; the parity-folded top
	// window is covered by TestGeneratorCompleteFinalAddition.
	table := p256Comb(c.Window).windows[1]
	got := cv.combSelect(table, c.Bits, true)
	cv.fp.AssertZero(T(1, got.X), T(-1, cv.fp.FromLimbs(c.X[:])))
	cv.fp.AssertZero(T(1, got.Y), T(-1, cv.fp.FromLimbs(c.Y[:])))
	return nil
}

func TestCombSelectEverySignedRow(t *testing.T) {
	for _, w := range []int{5, 6, 7, 8} {
		circuit := &combSelectCircuit{Window: w, Bits: make([]frontend.Variable, w)}
		cs := compile(t, circuit)
		table := p256Comb(w).windows[1]
		for index, point := range table {
			assignment := &combSelectCircuit{Bits: make([]frontend.Variable, w), X: plainLimbValues(point[0]), Y: plainLimbValues(point[1])}
			for bit := range assignment.Bits {
				assignment.Bits[bit] = (index >> bit) & 1
			}
			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(witness); err != nil {
				t.Fatalf("window=%d index=%d: %v", w, index, err)
			}
		}
	}
}
