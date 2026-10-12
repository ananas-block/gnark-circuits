package p256

import (
	"strings"
	"testing"

	"github.com/consensys/gnark/constraint/solver"

	"github.com/ananas-block/gnark-circuits/internal/lookup"
)

const modulePrefix = "github.com/ananas-block/gnark-circuits/p256"

func TestHintNamesCarryTheModulePrefix(t *testing.T) {
	for _, fn := range []solver.Hint{
		p256RatioHint, p256TangentHint, p256AddHint,
		p256DecomposeScalarHint, p256ScalarMulHint, p256ImplicitChordHint, p256ImplicitSecondSlopeHint,
		p256CombRecodeHint, p256CombChainHint, p256XEqualHint, p256UnifiedSlopeHint,
		lookup.RowLookupHint, lookup.RowCountHint,
		p256ScalarInverseHint, p256OrderWrapHint, p256LimbBytesHint, p256SplitLowBitsHint,
	} {
		name := solver.GetHintName(fn)
		if !strings.HasPrefix(name, modulePrefix+".") && !strings.HasPrefix(name, "github.com/ananas-block/gnark-circuits/internal/lookup.") {
			t.Fatalf("hint %s is not under %s", name, modulePrefix)
		}
		if solver.GetRegisteredHint(solver.GetHintID(fn)) == nil {
			t.Fatalf("hint %s is not registered", name)
		}
	}
}
