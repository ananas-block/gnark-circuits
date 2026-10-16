package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestX25519AgreementRows(t *testing.T) {
	found := 0
	for _, row := range rows() {
		if row.section != sectionX25519 || !strings.Contains(row.name, "key agreement") {
			continue
		}
		found++
		for _, n := range []int{1, 10} {
			t.Run(fmt.Sprintf("%s/x%d", row.name, n), func(t *testing.T) {
				blank, assignment, err := row.circuits(n)
				if err != nil {
					t.Fatal(err)
				}
				cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, blank)
				if err != nil {
					t.Fatal(err)
				}
				witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if err := cs.IsSolved(witness); err != nil {
					t.Fatal(err)
				}
				if cs.GetNbPublicVariables() != 6*n+1 {
					t.Fatalf("public inputs=%d; want six outputs per instance", cs.GetNbPublicVariables())
				}
				t.Logf("%d constraints", cs.GetNbConstraints())
			})
		}
	}
	if found != 1 {
		t.Fatalf("found%d full X25519 rows; want lookup", found)
	}
}
