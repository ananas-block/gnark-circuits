package emfield

import (
	"errors"
	"math/big"
)

func Unwrap(q *big.Int, inputs, outputs []*big.Int, fn func(mod *big.Int, natives, in, out []*big.Int) error) error {
	lay, err := layoutOf(inputs)
	if err != nil {
		return err
	}
	n := lay.NbLimbs
	pos := headerLen
	if len(inputs) < pos+n+1 {
		return errors.New("missing hint header")
	}
	mod := lay.recompose(inputs[pos : pos+n])
	pos += n
	nbNatives := int(inputs[pos].Int64())
	pos++
	natives := inputs[pos : pos+nbNatives]
	pos += nbNatives
	var in []*big.Int
	for pos < len(inputs) {
		nl := int(inputs[pos].Int64())
		pos++
		limbs := make([]*big.Int, nl)
		for j := range limbs {
			limbs[j] = signed(inputs[pos+j], q)
		}
		pos += nl
		in = append(in, lay.recompose(limbs))
	}
	widths := lay.reducedWidths(mod.BitLen())
	per := lay.nbPiecesAll(widths)
	if len(outputs)%per != 0 {
		return errors.New("output count is not a multiple of the element size")
	}
	out := make([]*big.Int, len(outputs)/per)
	for i := range out {
		out[i] = new(big.Int)
	}
	if err := fn(mod, natives, in, out); err != nil {
		return err
	}
	rest := outputs
	for _, v := range out {
		rest = lay.writePieces(rest, new(big.Int).Mod(v, mod), widths)
	}
	return nil
}
