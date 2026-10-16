package encryption

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	gadget "zolana/prover/circuits/gadget"
)

const (
	DomSepSilo  uint32 = 0x544d5349
	DomSepKey   uint32 = 0x544d534b
	DomSepKeyHi uint32 = 0x544d534c
	DomSepNonce uint32 = 0x544d534e

	KeyBytes   = 32
	NonceBytes = 12
	byteBits   = 8

	maxKdfInfoBytes = 14 * gadget.HashBytesChunkSize
)

func KeySchedule(
	api frontend.API,
	sharedSecret frontend.Variable,
	info []byte,
) (key [KeyBytes]frontend.Variable, nonce [NonceBytes]frontend.Variable) {
	if len(info) > maxKdfInfoBytes {
		panic(fmt.Sprintf("kdf: info of %d bytes, at most %d", len(info), maxKdfInfoBytes))
	}
	if len(info) > 0 {
		lastChunk := (len(info) - 1) / gadget.HashBytesChunkSize * gadget.HashBytesChunkSize
		if info[lastChunk] == 0 {
			panic("kdf: final info chunk must not start with zero")
		}
	}
	infoBytes := make([]frontend.Variable, len(info))
	for i, b := range info {
		infoBytes[i] = b
	}
	infoFields := gadget.PackBytesBE(api, infoBytes)

	siloInputs := []frontend.Variable{
		frontend.Variable(uint64(DomSepSilo)),
		sharedSecret,
	}
	siloInputs = append(siloInputs, infoFields...)
	siloed := gadget.PoseidonHash(api, siloInputs)

	keyLo := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepKey)),
		siloed,
	})
	keyHi := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepKeyHi)),
		siloed,
	})

	keyLoBytes := FieldToBytesBE(api, keyLo, 32)
	keyHiBytes := FieldToBytesBE(api, keyHi, 32)
	for i := 0; i < 16; i++ {
		key[i] = keyHiBytes[16+i]
		key[16+i] = keyLoBytes[16+i]
	}

	nonceRaw := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepNonce)),
		siloed,
	})
	nonceBytes := FieldToBytesBE(api, nonceRaw, 32)
	for i := 0; i < NonceBytes; i++ {
		nonce[i] = nonceBytes[20+i]
	}

	return key, nonce
}

func FieldToBytesBE(api frontend.API, v frontend.Variable, nbytes int) []frontend.Variable {
	b := bits.ToBinary(api, v, bits.WithNbDigits(nbytes*byteBits))
	out := make([]frontend.Variable, nbytes)
	for i := range out {
		start := (nbytes - 1 - i) * byteBits
		out[i] = api.FromBinary(b[start : start+byteBits]...)
	}
	return out
}
