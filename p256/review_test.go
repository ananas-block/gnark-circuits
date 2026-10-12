package p256

// Regression tests for the input and completeness defects in docs/p256-review.md.
import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func reviewSolve(t *testing.T, cs constraint.ConstraintSystem, w frontend.Circuit, accept bool) {
	t.Helper()
	wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	err = cs.IsSolved(wit)
	if (err == nil) != accept {
		t.Fatalf("accept=%v: %v", accept, err)
	}
	if err != nil && !strings.Contains(err.Error(), "is not satisfied") {
		t.Fatalf("not a constraint rejection: %v", err)
	}
}

func TestReviewMalformedECDHEncoding(t *testing.T) {
	cs := compile(t, &ecdhCircuit{})
	row := scalarRow{scalar: mergeScalar, reduced: mergeScalar}
	peer := peerKey(t).PublicKey()
	honest := row.ecdhWitness(t, peer)
	reviewSolve(t, cs, honest, true)
	t.Run("wrong prefix", func(t *testing.T) {
		w := *honest
		w.PublicKey[0] = 5
		bad := append([]byte{}, peer.Bytes()...)
		bad[0] = 5
		if _, err := ecdh.P256().NewPublicKey(bad); err == nil {
			t.Fatal("host accepted malformed key")
		}
		reviewSolve(t, cs, &w, false)
	})
	t.Run("non byte coordinate", func(t *testing.T) {
		w := *honest
		w.PublicKey[1] = int(peer.Bytes()[1]) - 1
		w.PublicKey[2] = int(peer.Bytes()[2]) + 256
		reviewSolve(t, cs, &w, false)
	})
	t.Run("noncanonical x", func(t *testing.T) {
		x, y := smallCurvePoint(t)
		key, err := ecdh.P256().NewPublicKey(elliptic.Marshal(elliptic.P256(), x, y))
		if err != nil {
			t.Fatal(err)
		}
		w := row.ecdhWitness(t, key)
		alias := new(big.Int).Add(x, elliptic.P256().Params().P)
		setBytes(w.PublicKey[1:33], alias.FillBytes(make([]byte, 32)))
		reviewSolve(t, cs, w, false)
	})
}

func TestReviewScalarByteAlias(t *testing.T) {
	cs := compile(t, &agreeKeyCircuit{})
	w := agreeKeyWitness(t, mergeScalar, peerKey(t).PublicKey())
	raw := mergeScalar.FillBytes(make([]byte, 32))
	w.Scalar[1] = int(raw[1]) - 1
	w.Scalar[2] = int(raw[2]) + 256
	reviewSolve(t, cs, w, false)
}

type reviewScalarMulCircuit struct {
	Scalar            [32]frontend.Variable
	PublicKey, Result [65]frontend.Variable
}

func (c *reviewScalarMulCircuit) Define(api frontend.API) error {
	result := ScalarMul(api, c.Scalar, c.PublicKey)
	assertBytesEqual(api, result[:], c.Result[:])
	return nil
}

func TestReviewExceptionalScalarMulCoordinates(t *testing.T) {
	peer := peerKey(t).PublicKey().Bytes()
	px, py := elliptic.Unmarshal(elliptic.P256(), peer)
	cs := compile(t, &reviewScalarMulCircuit{})
	for _, row := range scalarRows(t) {
		if row.reduced == nil {
			continue
		}
		t.Run(row.name, func(t *testing.T) {
			w := &reviewScalarMulCircuit{}
			setBytes(w.Scalar[:], row.scalar.FillBytes(make([]byte, 32)))
			setBytes(w.PublicKey[:], peer)
			x, y := elliptic.P256().ScalarMult(px, py, row.reduced.Bytes())
			setBytes(w.Result[:], elliptic.Marshal(elliptic.P256(), x, y))
			reviewSolve(t, cs, w, true)
			// ECDH's X alone cannot distinguish a sign error; assert full Y,
			// then make that coordinate incorrect and require rejection.
			w.Result[64] = int(y.FillBytes(make([]byte, 32))[31]) ^ 1
			reviewSolve(t, cs, w, false)
		})
	}
}

func TestReviewECDSACompleteness(t *testing.T) {
	cs := compile(t, &ecdsaCircuit{})
	for _, row := range []struct {
		name   string
		u1, u2 int64
		accept bool
	}{
		{"ordinary", 7, 11, true}, {"zero hash", 0, 11, true}, {"r equals s", 7, 1, true}, {"u2 equals three", 7, 3, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			v := vectorWithScalars(t, big.NewInt(19), big.NewInt(row.u1), big.NewInt(row.u2))
			if !v.hostVerifies() {
				t.Fatal("invalid reference signature")
			}
			reviewSolve(t, cs, v.witness(), row.accept)
		})
	}
}

type reviewAddCircuit struct {
	PX, PY, QX, QY, X, Y [8]frontend.Variable
}

func (c *reviewAddCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	p := &point{cv.fp.FromLimbs(c.PX[:]), cv.fp.FromLimbs(c.PY[:])}
	q := &point{cv.fp.FromLimbs(c.QX[:]), cv.fp.FromLimbs(c.QY[:])}
	cv.assertOnCurve(p)
	cv.assertOnCurve(q)
	r := cv.completeAdd(p, q)
	cv.assertEqual(r, &point{cv.fp.FromLimbs(c.X[:]), cv.fp.FromLimbs(c.Y[:])})
	return nil
}

func TestReviewNativeDistinctCollision(t *testing.T) {
	params := elliptic.P256().Params()
	sqrt := func(x *big.Int) *big.Int {
		r := new(big.Int).Exp(x, big.NewInt(3), params.P)
		r.Sub(r, new(big.Int).Mul(big.NewInt(3), x)).Add(r, params.B).Mod(r, params.P)
		return new(big.Int).ModSqrt(r, params.P)
	}
	var px, py, qx, qy *big.Int
	for i := int64(0); i < 1000; i++ {
		px = big.NewInt(i)
		qx = new(big.Int).Add(px, ecc.BN254.ScalarField())
		py, qy = sqrt(px), sqrt(qx)
		if py != nil && qy != nil {
			break
		}
	}
	if py == nil || qy == nil {
		t.Fatal("no collision points found")
	}
	x, y := elliptic.P256().Add(px, py, qx, qy)
	t.Logf("valid unequal x coordinates: %s and %s", px, qx)
	cs := compile(t, &reviewAddCircuit{})
	w := &reviewAddCircuit{PX: plainLimbValues(px), PY: plainLimbValues(py), QX: plainLimbValues(qx), QY: plainLimbValues(qy), X: plainLimbValues(x), Y: plainLimbValues(y)}
	reviewSolve(t, cs, w, true)
	// Control: doubling the same valid point succeeds.
	x, y = elliptic.P256().Double(px, py)
	w.QX, w.QY, w.X, w.Y = w.PX, w.PY, plainLimbValues(x), plainLimbValues(y)
	reviewSolve(t, cs, w, true)
	x, y = elliptic.P256().Add(px, py, qx, qy)
}

func TestReviewECDSANativeCollision(t *testing.T) {
	curve := elliptic.P256()
	p, n := curve.Params().P, GroupOrder()
	var v ecdsaVector
	for u1 := int64(1); u1 < 100; u1++ {
		ax, ay := curve.ScalarBaseMult(big.NewInt(u1).Bytes())
		bx := new(big.Int).Add(ax, ecc.BN254.ScalarField())
		if bx.Cmp(p) >= 0 {
			continue
		}
		rhs := new(big.Int).Exp(bx, big.NewInt(3), p)
		rhs.Sub(rhs, new(big.Int).Mul(bx, big.NewInt(3))).Add(rhs, curve.Params().B).Mod(rhs, p)
		by := new(big.Int).ModSqrt(rhs, p)
		if by == nil {
			continue
		}
		qx, qy := curve.ScalarMult(bx, by, new(big.Int).ModInverse(big.NewInt(2), n).Bytes())
		rx, _ := curve.Add(ax, ay, bx, by)
		r := new(big.Int).Mod(rx, n)
		s := new(big.Int).Mul(r, new(big.Int).ModInverse(big.NewInt(2), n))
		s.Mod(s, n)
		h := new(big.Int).Mul(big.NewInt(u1), s)
		h.Mod(h, n)
		v = ecdsaVector{x: qx, y: qy, h: h, r: r, s: s}
		if !v.hostVerifies() {
			t.Fatal("invalid reference signature")
		}
		t.Logf("u1=%d u2=2", u1)
		break
	}
	if v.x == nil {
		t.Fatal("no vector found")
	}
	cs := compile(t, &ecdsaCircuit{})
	hit := false
	record := solver.OverrideHint(solver.GetHintID(p256XEqualHint), func(q *big.Int, inputs, outputs []*big.Int) error {
		width, limbs := inputs[0], inputs[1:]
		half := len(limbs) / 2
		x1 := limbHintValue(append([]*big.Int{width}, limbs[:half]...))
		x2 := limbHintValue(append([]*big.Int{width}, limbs[half:]...))
		d := new(big.Int).Sub(x1, x2)
		hit = hit || (d.Sign() != 0 && new(big.Int).Mod(d, q).Sign() == 0)
		return p256XEqualHint(q, inputs, outputs)
	})
	if err := solveECDSA(t, cs, v.witness(), record); err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Fatal("did not reach the colliding addition")
	}
}

func TestReviewXOnlyCost(t *testing.T) {
	xOnly := compile(t, &ecdhCircuit{})
	full := compile(t, &reviewFullECDHCircuit{})
	t.Logf("ECDH full=%d x-only=%d saved=%d", full.GetNbConstraints(), xOnly.GetNbConstraints(), full.GetNbConstraints()-xOnly.GetNbConstraints())
}

type reviewFullECDHCircuit struct {
	Scalar    [32]frontend.Variable
	PublicKey [65]frontend.Variable
	Shared    [32]frontend.Variable `gnark:",public"`
}

func (c *reviewFullECDHCircuit) Define(api frontend.API) error {
	result := ScalarMul(api, c.Scalar, c.PublicKey)
	assertBytesEqual(api, result[1:33], c.Shared[:])
	return nil
}

type reviewWideRelimbCircuit struct {
	Input  frontend.Variable
	Output [8]frontend.Variable `gnark:",public"`
}

func (c *reviewWideRelimbCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	out := cv.relimb([]frontend.Variable{c.Input}, 256)
	for i := range out {
		api.AssertIsEqual(out[i], c.Output[i])
	}
	return nil
}

func TestReviewWideRelimbRejected(t *testing.T) {
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &reviewWideRelimbCircuit{})
	if err == nil || !strings.Contains(err.Error(), "limbs do not tile the field layout") {
		t.Fatalf("expected layout rejection, got %v", err)
	}
}
