package aes

import (
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark/frontend"
)

const (
	aes256KeyBytes   = 32
	aes256Rounds     = 14
	aes256RoundBytes = 16 * (aes256Rounds + 1)
	blockBytes       = 16
	bitsPerByte      = 8
	wordBytes        = 4
	columnsPerBlock  = blockBytes / wordBytes

	ctrFirstCounter = 2

	maxCtrBlocks = 1<<32 - ctrFirstCounter
)

type Cipher struct {
	keys *roundKeys
}

func NewCipher(api frontend.API, key [aes256KeyBytes]frontend.Variable) *Cipher {
	return &Cipher{keys: expandRoundKeys(api, key)}
}

func (c *Cipher) CTREncrypt(nonceBytes [12]frontend.Variable, plaintext []frontend.Variable) []frontend.Variable {

	if blocks := (len(plaintext) + blockBytes - 1) / blockBytes; blocks > maxCtrBlocks {
		panic(fmt.Sprintf("ctr: %d blocks wrap the 32-bit counter, at most %d", blocks, maxCtrBlocks))
	}

	keys := c.keys
	t := keys.tables
	spreadNonce := make([]frontend.Variable, len(nonceBytes))
	for i := range nonceBytes {
		spreadNonce[i] = t.spreadByte(nonceBytes[i])
	}

	stream := &ctrStream{keys: keys, nonceState: keys.addRoundKey(spreadNonce, 0), cachedHigh: -1}

	ciphertext := make([]frontend.Variable, 0, len(plaintext))
	for offset := 0; offset < len(plaintext); offset += blockBytes {
		end := min(offset+blockBytes, len(plaintext))
		counter := uint32(offset/blockBytes + ctrFirstCounter)
		ciphertext = append(ciphertext, stream.encryptBlock(counter, plaintext[offset:end])...)
	}
	return ciphertext
}

type ctrStream struct {
	keys       *roundKeys
	nonceState []frontend.Variable
	cachedHigh int64
	firstRound [blockBytes]frontend.Variable
	columnZero frontend.Variable
}

func (s *ctrStream) encryptBlock(counter uint32, plaintextBytes []frontend.Variable) []frontend.Variable {
	var counterBytes [4]byte
	binary.BigEndian.PutUint32(counterBytes[:], counter)

	t := s.keys.tables
	spreadPlaintext := make([]frontend.Variable, len(plaintextBytes))
	for i, value := range plaintextBytes {
		spreadPlaintext[i] = t.spreadByte(value)
	}

	high := int64(counter >> bitsPerByte)
	if high != s.cachedHigh {
		s.cachedHigh = high
		var state [blockBytes]frontend.Variable
		copy(state[:12], s.nonceState)
		for counterByteIndex, counterByte := range counterBytes[:3] {
			position := len(s.nonceState) + counterByteIndex
			state[position] = s.counterByte(position, counterByte)
		}
		for column := 1; column < columnsPerBlock; column++ {
			start := column * wordBytes
			end := start + wordBytes
			copy(s.firstRound[start:end], s.keys.roundColumn(1, column, &state))
		}
		s.columnZero = s.keys.columnSum(1, 0, &state, 0, 1, 2)
	}

	last := s.counterByte(blockBytes-1, counterBytes[3])
	state := s.firstRound
	spreadCounterContribution := t.substitute(3, last)
	spreadColumnSum := t.api.Add(s.columnZero, spreadCounterContribution)
	columnBytes := t.decodeWordSum(spreadColumnSum, wordBytes)
	copy(state[:wordBytes], columnBytes)

	for round := 2; round < aes256Rounds; round++ {
		var next [blockBytes]frontend.Variable
		for column := 0; column < columnsPerBlock; column++ {
			start := column * wordBytes
			end := start + wordBytes
			copy(next[start:end], s.keys.roundColumn(round, column, &state))
		}
		state = next
	}

	spreadFinalRoundKey := s.keys.spreadBytes[aes256Rounds*blockBytes:]
	return t.finalRound(state[:], spreadFinalRoundKey, spreadPlaintext)
}

func (t *spreadTables) finalRoundConstrained(state, spreadFinalRoundKey, spreadPlaintext []frontend.Variable) []frontend.Variable {
	sums := make([]frontend.Variable, len(spreadPlaintext))
	for i := range sums {
		spreadSubstitutedByte := t.substitute(sboxRegion, state[byteOrder[i]])
		spreadRoundKeyByte := spreadFinalRoundKey[i]
		sums[i] = t.api.Add(spreadSubstitutedByte, spreadRoundKeyByte, spreadPlaintext[i])
	}
	return t.decodeByteSums(sums)
}

func (s *ctrStream) counterByte(position int, value byte) frontend.Variable {
	if value == 0 {
		return s.keys.bytes[position]
	}
	return s.keys.tables.counterByte(s.keys.spreadBytes[position], value)
}

func (t *spreadTables) counterByteConstrained(spreadKeyByte frontend.Variable, value byte) frontend.Variable {
	spreadCounterByte := t.spreadConstant(value)
	sum := t.api.Add(spreadKeyByte, spreadCounterByte)
	return t.decodeByteSums([]frontend.Variable{sum})[0]
}

type roundKeys struct {
	tables      *spreadTables
	spreadBytes []frontend.Variable
	bytes       []frontend.Variable
}

var roundConstants = [...]byte{0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

func expandRoundKeysConstrained(api frontend.API, key [aes256KeyBytes]frontend.Variable) *roundKeys {
	t := sharedSpreadTables(api)

	spreadRoundKeyBytes := make([]frontend.Variable, aes256RoundBytes)
	roundKeyBytes := make([]frontend.Variable, aes256RoundBytes)
	for i := 0; i < aes256KeyBytes; i++ {
		roundKeyBytes[i] = key[i]
		spreadRoundKeyBytes[i] = t.spreadByte(key[i])
	}
	for i := aes256KeyBytes; i < aes256RoundBytes; i += wordBytes {
		previousWordBytes := roundKeyBytes[i-wordBytes : i]
		spreadPreviousWordBytes := spreadRoundKeyBytes[i-wordBytes : i]
		earlierWordStart := i - aes256KeyBytes
		spreadEarlierWordBytes := spreadRoundKeyBytes[earlierWordStart : earlierWordStart+wordBytes]
		currentWordBytes := roundKeyBytes[i : i+wordBytes]
		spreadCurrentWordBytes := spreadRoundKeyBytes[i : i+wordBytes]

		var mixed [wordBytes]frontend.Variable
		switch i % aes256KeyBytes {
		case 0:
			for j := range mixed {
				rotatedByteIndex := (j + 1) % wordBytes
				previousByte := previousWordBytes[rotatedByteIndex]
				mixed[j] = t.substitute(sboxRegion, previousByte)
			}
			roundConstant := roundConstants[i/aes256KeyBytes]
			spreadRoundConstant := t.spreadConstant(roundConstant)
			mixed[0] = api.Add(mixed[0], spreadRoundConstant)
		case 16:
			for j := range mixed {
				previousByte := previousWordBytes[j]
				mixed[j] = t.substitute(sboxRegion, previousByte)
			}
		default:
			copy(mixed[:], spreadPreviousWordBytes)
		}
		sums := make([]frontend.Variable, wordBytes)
		for j := range sums {
			sums[j] = api.Add(spreadEarlierWordBytes[j], mixed[j])
		}
		copy(currentWordBytes, t.decodeByteSums(sums))
		for j, roundKeyByte := range currentWordBytes {
			spreadCurrentWordBytes[j] = t.spreadByte(roundKeyByte)
		}
	}
	return &roundKeys{tables: t, spreadBytes: spreadRoundKeyBytes, bytes: roundKeyBytes}
}

func (k *roundKeys) addRoundKey(spreadBytes []frontend.Variable, offset int) []frontend.Variable {
	sums := make([]frontend.Variable, len(spreadBytes))
	for i := range sums {
		sums[i] = k.tables.api.Add(spreadBytes[i], k.spreadBytes[offset+i])
	}
	return k.tables.decodeByteSums(sums)
}

func (k *roundKeys) roundColumnConstrained(round, column int, state *[blockBytes]frontend.Variable) []frontend.Variable {
	spreadColumnSum := k.columnSum(round, column, state, 0, 1, 2, 3)
	return k.tables.decodeWordSum(spreadColumnSum, wordBytes)
}

var columnSources = [columnsPerBlock][wordBytes]int{
	{0, 5, 10, 15},
	{4, 9, 14, 3},
	{8, 13, 2, 7},
	{12, 1, 6, 11},
}

func (k *roundKeys) columnSum(round, column int, state *[blockBytes]frontend.Variable, regions ...int) frontend.Variable {
	spreadRoundKeyWord, sources := k.columnInputs(round, column, state)
	return k.tables.columnSumOf(spreadRoundKeyWord, sources, regions...)
}

func (k *roundKeys) columnInputs(round, column int, state *[blockBytes]frontend.Variable) (spreadRoundKeyWord, sources []frontend.Variable) {
	start := round*blockBytes + column*wordBytes
	end := start + wordBytes
	sources = make([]frontend.Variable, wordBytes)
	for region := range sources {
		sources[region] = state[columnSources[column][region]]
	}
	return k.spreadBytes[start:end], sources
}

func (t *spreadTables) columnSumOf(spreadRoundKeyWord, sources []frontend.Variable, regions ...int) frontend.Variable {
	sum := t.packSpreadWord(spreadRoundKeyWord)
	for _, region := range regions {
		spreadContribution := t.substitute(region, sources[region])
		sum = t.api.Add(sum, spreadContribution)
	}
	return sum
}
