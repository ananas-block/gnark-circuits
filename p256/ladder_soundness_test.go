package p256

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/ananas-block/gnark-circuits/p256/emfield"
)

// This wrapper mutates the standalone step's single output guard. The tests
// require a false on-curve result to pass the mutant and fail the real step.
type omitLadderOutputGuardAPI struct{ frontend.API }

func (omitLadderOutputGuardAPI) AssertIsDifferent(frontend.Variable, frontend.Variable) {}

type ladderStepCircuit struct {
	OmitGuard, OmitCurve bool `gnark:"-"`
	A, Table, Expected   [2][8]frontend.Variable
}

func (c *ladderStepCircuit) Define(api frontend.API) error {
	if c.OmitGuard {
		api = omitLadderOutputGuardAPI{api}
	}
	cv := newCurve(api)
	pointFrom := func(v [2][8]frontend.Variable) *point {
		return &point{X: cv.fp.FromLimbs(v[0][:]), Y: cv.fp.FromLimbs(v[1][:])}
	}
	a, table := pointFrom(c.A), pointFrom(c.Table)
	cv.assertOnCurve(a)
	cv.assertOnCurve(table)
	got := cv.quadrupleAndAddLazy(a, table)
	if !c.OmitCurve {
		cv.assertOnCurve(got)
	}
	cv.assertEqual(got, pointFrom(c.Expected))
	return nil
}

func fixedLadderChord(value int64) solver.Hint {
	return func(q *big.Int, inputs, outputs []*big.Int) error {
		return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, _, out []*big.Int) error {
			out[0].Mod(big.NewInt(value), p)
			return nil
		})
	}
}

func ladderStepWitness(ax, ay, tx, ty, rx, ry *big.Int) *ladderStepCircuit {
	return &ladderStepCircuit{
		A:        [2][8]frontend.Variable{plainLimbValues(ax), plainLimbValues(ay)},
		Table:    [2][8]frontend.Variable{plainLimbValues(tx), plainLimbValues(ty)},
		Expected: [2][8]frontend.Variable{plainLimbValues(rx), plainLimbValues(ry)},
	}
}

func solveLadderStep(t *testing.T, circuit, assignment *ladderStepCircuit, opts ...solver.Option) error {
	t.Helper()
	cs := compile(t, circuit)
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return cs.IsSolved(w, opts...)
}

func erasurePoint(t *testing.T) (ax, ay, dx, dy *big.Int) {
	t.Helper()
	hex := func(value string) *big.Int {
		v, ok := new(big.Int).SetString(value, 16)
		if !ok {
			t.Fatal("invalid erasure test constant")
		}
		return v
	}
	ax = hex("34566de13c261a68b139c9adce7ae70ac0ed78c5e9ef984b9d26cdfc69668df6")
	ay = hex("fbae09c7d42c740e57c128d6d3c20434d934f7ac5723b2a9529b262c7b9f5758")
	dx = hex("e390994bbc3ef0c9b811aa056a405580e59f7bb307e38e62e4cbb8631880ffd4")
	dy = hex("556397cb6979a4b55069fc207d82010561bce62d2f5556515cc652529305fef5")
	curve := elliptic.P256()
	x, y := curve.Double(ax, ay)
	if !curve.IsOnCurve(ax, ay) || x.Cmp(dx) != 0 || y.Cmp(dy) != 0 {
		t.Fatal("erasure test needs D = 2A on P-256")
	}
	return
}

func TestFinalCurveCheckNeedsLadderOutputGuard(t *testing.T) {
	ax, ay, dx, dy := erasurePoint(t)
	p := elliptic.P256().Params().P
	w := ladderStepWitness(ax, ay, dx, dy, dx, new(big.Int).Sub(p, dy))
	forgery := solver.OverrideHint(solver.GetHintID(p256ImplicitChordHint), fixedLadderChord(2))
	// lambda=2, mu=-4 satisfy both slope equations, while the result is
	// -D instead of 3D. A final curve check alone accepts this forgery.
	if err := solveLadderStep(t, &ladderStepCircuit{OmitGuard: true}, w, forgery); err != nil {
		t.Fatalf("mutation did not expose the on-curve forgery: %v", err)
	}
	if err := solveLadderStep(t, &ladderStepCircuit{}, w, forgery); err == nil {
		t.Fatal("wrong on-curve result accepted with the output guard")
	}
}

func TestLadderOutputGuardNeedsFinalCurveCheck(t *testing.T) {
	ax, ay, dx, dy := erasurePoint(t)
	p := elliptic.P256().Params().P
	lambda := big.NewInt(3)
	x2 := new(big.Int).Sub(big.NewInt(9), new(big.Int).Lsh(dx, 1))
	mu := modRatio(p, new(big.Int).Lsh(dy, 1), new(big.Int).Sub(x2, dx))
	sum := new(big.Int).Add(mu, new(big.Int).Lsh(lambda, 1))
	rx := new(big.Int).Add(dx, new(big.Int).Mul(mu, sum))
	rx.Mod(rx, p)
	ry := new(big.Int).Mul(new(big.Int).Add(lambda, mu), new(big.Int).Sub(rx, dx))
	ry.Sub(ry, dy).Mod(ry, p)
	if elliptic.P256().IsOnCurve(rx, ry) {
		t.Fatal("test forgery unexpectedly lies on P-256")
	}
	w := ladderStepWitness(ax, ay, dx, dy, rx, ry)
	forgery := solver.OverrideHint(solver.GetHintID(p256ImplicitChordHint), fixedLadderChord(3))
	if err := solveLadderStep(t, &ladderStepCircuit{OmitCurve: true}, w, forgery); err != nil {
		t.Fatalf("mutation did not expose the off-curve forgery: %v", err)
	}
	if err := solveLadderStep(t, &ladderStepCircuit{}, w, forgery); err == nil {
		t.Fatal("wrong off-curve result accepted with the final curve check")
	}
}

func TestLadderStepHandlesEqualPointWithTangent(t *testing.T) {
	ax, ay, dx, dy := erasurePoint(t)
	rx, ry := elliptic.P256().ScalarMult(dx, dy, []byte{3})
	w := ladderStepWitness(ax, ay, dx, dy, rx, ry)
	if err := solveLadderStep(t, &ladderStepCircuit{}, w); err != nil {
		t.Fatalf("equal-point tangent rejected: %v", err)
	}
}
