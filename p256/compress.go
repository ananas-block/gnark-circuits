package p256

import "github.com/consensys/gnark/frontend"

func CompressPubkey(api frontend.API, uncompressed [65]frontend.Variable) [33]frontend.Variable {
	bits := api.ToBinary(uncompressed[64], 8)
	parity := bits[0]

	var compressed [33]frontend.Variable
	compressed[0] = api.Add(2, parity)
	for i := 0; i < 32; i++ {
		compressed[1+i] = uncompressed[1+i]
	}
	return compressed
}
