package aes

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

const (
	spreadBase       = 6
	digitsPerChunk   = 4
	chunkRadix       = 1296
	chunksPerByte    = bitsPerByte / digitsPerChunk
	nibbleRadix      = 1 << digitsPerChunk
	tableRegionSize  = 256
	sboxRegion       = 4
	substitutionSize = 5 * tableRegionSize
)

type spreadTables struct {
	api          frontend.API
	byteWeights  [wordBytes]*big.Int
	substitution logderivlookup.Table
	bytes        logderivlookup.Table
	chunks       logderivlookup.Table
}

type compilerStore interface {
	SetKeyValue(key, value any)
	GetKeyValue(key any) any
}

type spreadTablesKey struct{}

func sharedSpreadTables(api frontend.API) *spreadTables {
	store, supportsCaching := api.Compiler().(compilerStore)
	if supportsCaching {
		if cachedTables, ok := store.GetKeyValue(spreadTablesKey{}).(*spreadTables); ok {
			return cachedTables
		}
	}
	tables := newSpreadTables(api)
	if supportsCaching {
		store.SetKeyValue(spreadTablesKey{}, tables)
	}
	return tables
}

func newSpreadTables(api frontend.API) *spreadTables {
	t := &spreadTables{api: api}

	base := big.NewInt(spreadBase)
	for byteIndex := range t.byteWeights {
		exponent := big.NewInt(int64(bitsPerByte * byteIndex))
		t.byteWeights[byteIndex] = new(big.Int).Exp(base, exponent, nil)
	}

	t.substitution = logderivlookup.New(api)
	for _, entry := range SubstitutionTable() {
		t.substitution.Insert(entry)
	}
	t.bytes = logderivlookup.New(api)
	for _, entry := range SpreadByteTable() {
		t.bytes.Insert(entry)
	}
	t.chunks = logderivlookup.New(api)
	for _, entry := range ChunkParityTable() {
		t.chunks.Insert(entry)
	}
	return t
}

func (t *spreadTables) substitute(region int, index frontend.Variable) frontend.Variable {
	regionOffset := region * tableRegionSize
	lookupIndex := t.api.Add(index, regionOffset)
	return t.substitution.Lookup(lookupIndex)[0]
}

func (t *spreadTables) spreadByte(value frontend.Variable) frontend.Variable {
	return t.bytes.Lookup(value)[0]
}

func (t *spreadTables) spreadConstant(value byte) *big.Int {
	return spreadValue(uint64(value), bitsPerByte)
}

func (t *spreadTables) decodeByteSums(spreadByteSums []frontend.Variable) []frontend.Variable {
	decodedBytes := make([]frontend.Variable, 0, len(spreadByteSums))
	for start := 0; start < len(spreadByteSums); start += wordBytes {
		end := min(start+wordBytes, len(spreadByteSums))
		spreadWordSum := t.packSpreadWord(spreadByteSums[start:end])
		decodedWordBytes := t.decodeWordSum(spreadWordSum, end-start)
		decodedBytes = append(decodedBytes, decodedWordBytes...)
	}
	return decodedBytes
}

func (t *spreadTables) packSpreadWord(spreadByteSums []frontend.Variable) frontend.Variable {
	var acc frontend.Variable = 0
	for byteIndex, spreadByteSum := range spreadByteSums {
		weightedByte := t.api.Mul(spreadByteSum, t.byteWeights[byteIndex])
		acc = t.api.Add(acc, weightedByte)
	}
	return acc
}

func (t *spreadTables) decodeWordSumConstrained(spreadSum frontend.Variable, byteCount int) []frontend.Variable {

	chunkCount := chunksPerByte * byteCount
	chunks, err := t.api.NewHint(laneChunksHint, chunkCount, spreadSum)
	if err != nil {
		panic(err)
	}

	var recomposed frontend.Variable = 0
	chunkWeight := big.NewInt(1)
	radix := big.NewInt(chunkRadix)
	for _, chunk := range chunks {
		weightedChunk := t.api.Mul(chunk, chunkWeight)
		recomposed = t.api.Add(recomposed, weightedChunk)
		chunkWeight = new(big.Int).Mul(chunkWeight, radix)
	}
	t.api.AssertIsEqual(spreadSum, recomposed)

	nibbles := t.chunks.Lookup(chunks...)

	decodedBytes := make([]frontend.Variable, byteCount)
	for byteIndex := range decodedBytes {
		chunkIndex := chunksPerByte * byteIndex
		lowNibble := nibbles[chunkIndex]
		highNibble := nibbles[chunkIndex+1]
		decodedBytes[byteIndex] = t.api.Add(lowNibble, t.api.Mul(highNibble, nibbleRadix))
	}
	return decodedBytes
}

func init() {
	solver.RegisterHint(laneChunksHint)
}

func laneChunksHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("lane chunks: expected one input, got %d", len(inputs))
	}
	remainingSum := new(big.Int).Set(inputs[0])
	radix := big.NewInt(chunkRadix)
	for _, chunk := range outputs {
		remainingSum.DivMod(remainingSum, radix, chunk)
	}
	if remainingSum.Sign() != 0 {
		return fmt.Errorf("lane chunks: sum exceeds %d chunks", len(outputs))
	}
	return nil
}

func spreadValue(value uint64, bitCount int) *big.Int {
	encodedValue := new(big.Int)
	bitWeight := big.NewInt(1)
	base := big.NewInt(spreadBase)
	for bitIndex := 0; bitIndex < bitCount; bitIndex++ {
		bitIsSet := (value>>uint(bitIndex))&1 == 1
		if bitIsSet {
			encodedValue.Add(encodedValue, bitWeight)
		}
		bitWeight.Mul(bitWeight, base)
	}
	return encodedValue
}

func chunkParity(chunk int) int {
	parity := 0
	for bitIndex := 0; bitIndex < digitsPerChunk; bitIndex++ {
		digit := chunk % spreadBase
		parityBit := digit % 2
		parity |= parityBit << uint(bitIndex)
		chunk /= spreadBase
	}
	return parity
}
