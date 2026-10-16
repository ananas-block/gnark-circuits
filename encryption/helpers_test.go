package encryption

import (
	"testing"

	"github.com/consensys/gnark/constraint"
)

func assertSinglePrivateCommitment(t *testing.T, ccs constraint.ConstraintSystem) {
	t.Helper()
	commitments, ok := ccs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 {
		t.Fatalf("want one Groth16 commitment, got %v", ccs.GetCommitments())
	}
	if n := len(commitments[0].PublicAndCommitmentCommitted); n != 0 {
		t.Fatalf("the commitment covers %d public wires", n)
	}
}
