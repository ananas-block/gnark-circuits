package aes

import (
	"github.com/consensys/gnark/frontend"
)

func (t *spreadTables) decodeWordSum(spreadSum frontend.Variable, byteCount int) []frontend.Variable {
	return t.decodeWordSumConstrained(spreadSum, byteCount)
}

func (k *roundKeys) roundColumn(round, column int, state *[blockBytes]frontend.Variable) []frontend.Variable {
	return k.roundColumnConstrained(round, column, state)
}

func (t *spreadTables) finalRound(state, spreadFinalRoundKey, spreadPlaintext []frontend.Variable) []frontend.Variable {
	return t.finalRoundConstrained(state, spreadFinalRoundKey, spreadPlaintext)
}

func (t *spreadTables) counterByte(spreadKeyByte frontend.Variable, value byte) frontend.Variable {
	return t.counterByteConstrained(spreadKeyByte, value)
}

func expandRoundKeys(api frontend.API, key [aes256KeyBytes]frontend.Variable) *roundKeys {
	return expandRoundKeysConstrained(api, key)
}
