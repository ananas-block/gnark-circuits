package r1c

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

func AssertProduct(api frontend.API, a, b, c frontend.Variable) {
	comp := api.Compiler()
	if va, okA := comp.ConstantValue(a); okA {
		if vb, okB := comp.ConstantValue(b); okB {
			if vc, okC := comp.ConstantValue(c); okC {
				p := comp.Field()
				lhs := new(big.Int).Mul(va, vb)
				lhs.Mod(lhs, p)
				if lhs.Cmp(new(big.Int).Mod(vc, p)) != 0 {
					panic(fmt.Sprintf("r1c: constant row %s * %s = %s does not hold", va, vb, vc))
				}
				return
			}
		}
	}
	AssertProductParts(api, []frontend.Variable{a}, []frontend.Variable{b}, []frontend.Variable{c})
}

func AssertProductParts(api frontend.API, a, b, c []frontend.Variable) {
	comp := api.Compiler()
	la, okA := r1cConcat(comp, a)
	lb, okB := r1cConcat(comp, b)
	lc, okC := r1cConcat(comp, c)
	kv, okKV := comp.(r1cKeyValueStore)
	if !okA || !okB || !okC || !okKV {
		api.AssertIsEqual(api.Mul(sum(api, a...), sum(api, b...)), sum(api, c...))
		return
	}
	bp, bID := r1cBlueprint(comp, kv)
	var calldata []uint32
	bp.CompressR1C(&constraint.R1C{L: la, R: lb, O: lc}, &calldata)
	comp.AddInstruction(bID, calldata)
}

func r1cConcat(comp frontend.Compiler, parts []frontend.Variable) (constraint.LinearExpression, bool) {
	var out constraint.LinearExpression
	for _, p := range parts {
		l, ok := comp.ToCanonicalVariable(p).(constraint.LinearExpression)
		if !ok {
			return nil, false
		}
		out = append(out, r1cOnConstantWire(l)...)
	}
	return out, true
}

type r1cKeyValueStore interface {
	SetKeyValue(key, value any)
	GetKeyValue(key any) any
}

type r1cBlueprintKey struct{}

type r1cBlueprintEntry struct {
	bp *constraint.BlueprintGenericR1C
	id constraint.BlueprintID
}

func r1cBlueprint(comp frontend.Compiler, kv r1cKeyValueStore) (*constraint.BlueprintGenericR1C, constraint.BlueprintID) {
	if v := kv.GetKeyValue(r1cBlueprintKey{}); v != nil {
		entry, ok := v.(r1cBlueprintEntry)
		if !ok {
			panic("r1c: stored blueprint has an unexpected type")
		}
		return entry.bp, entry.id
	}
	bp := &constraint.BlueprintGenericR1C{}
	id := comp.AddBlueprint(bp)
	kv.SetKeyValue(r1cBlueprintKey{}, r1cBlueprintEntry{bp: bp, id: id})
	return bp, id
}

func r1cOnConstantWire(l constraint.LinearExpression) constraint.LinearExpression {
	for i := range l {
		if l[i].IsConstant() {
			out := make(constraint.LinearExpression, len(l))
			copy(out, l)
			for j := range out {
				if out[j].IsConstant() {
					out[j].VID = 0
				}
			}
			return out
		}
	}
	return l
}

func sum(api frontend.API, vs ...frontend.Variable) frontend.Variable {
	if len(vs) == 0 {
		return 0
	}
	if len(vs) == 1 {
		return vs[0]
	}
	return api.Add(vs[0], vs[1], vs[2:]...)
}
