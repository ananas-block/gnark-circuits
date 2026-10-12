package p256

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/ananas-block/gnark-circuits/p256/emfield"
)

type ladderOutputGuardCircuit struct {
	A, B [8]frontend.Variable
}

func (c *ladderOutputGuardCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	a := cv.fp.HintBalanced(identityHint, 1, nil, cv.fp.FromLimbs(c.A[:]))[0]
	b := cv.fp.HintBalanced(identityHint, 1, nil, cv.fp.FromLimbs(c.B[:]))[0]
	cv.assertLadderOutputDistinct(a, b)
	return nil
}

func identityHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(_ *big.Int, _, in, out []*big.Int) error {
		out[0].Set(in[0])
		return nil
	})
}

func plainLimbValues(v *big.Int) (out [8]frontend.Variable) {
	for i := range out {
		out[i] = new(big.Int).And(new(big.Int).Rsh(v, uint(32*i)), big.NewInt(0xffffffff))
	}
	return out
}

func TestLadderOutputGuard(t *testing.T) {
	solver.RegisterHint(identityHint)
	cs := compile(t, &ladderOutputGuardCircuit{})
	p := elliptic.P256().Params().P
	x := new(big.Int).Sub(p, big.NewInt(0x1234_5678))
	third := new(big.Int).Div(p, big.NewInt(3))
	thirdRemainder := new(big.Int).Sub(p, new(big.Int).Lsh(third, 1))
	for _, row := range []struct {
		name   string
		a, b   *big.Int
		accept bool
	}{
		{"distinct", x, big.NewInt(0x1234_5679), true},
		{"equal nonzero", big.NewInt(7), big.NewInt(7), true},
		{"zero mu", big.NewInt(7), big.NewInt(0), false},
		{"zero sum", big.NewInt(7), new(big.Int).Sub(p, big.NewInt(14)), false},
		{"zero sum modulo p", new(big.Int).Sub(p, big.NewInt(7)), big.NewInt(14), false},
		{"sum integer p", third, thirdRemainder, false},
		{"sum integer minus p", new(big.Int).Sub(p, third), new(big.Int).Sub(p, thirdRemainder), false},
		{"zero both", big.NewInt(0), big.NewInt(0), false},
	} {
		w := &ladderOutputGuardCircuit{A: plainLimbValues(row.a), B: plainLimbValues(row.b)}
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); (err == nil) != row.accept {
			t.Fatalf("%s: accept=%v err=%v", row.name, row.accept, err)
		}
		if err := test.IsSolved(&ladderOutputGuardCircuit{}, w, ecc.BN254.ScalarField()); (err == nil) != row.accept {
			t.Fatalf("test engine %s: accept=%v err=%v", row.name, row.accept, err)
		}
	}
}
