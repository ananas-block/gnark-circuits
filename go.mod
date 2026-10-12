module github.com/ananas-block/gnark-circuits

go 1.27.1

require (
	github.com/consensys/gnark v0.16.4
	github.com/consensys/gnark-crypto v0.21.1-0.20260913224755-1409fe592052
	github.com/iden3/go-iden3-crypto v0.0.17
	zolana/prover v0.0.0-00010101000000-000000000000
)

require (
	github.com/bits-and-blooms/bitset v1.25.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/google/pprof v0.0.0-20260906184651-6331bc6350fe // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/reilabs/gnark-lean-extractor/v3 v3.0.0 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace zolana/prover => github.com/helius-labs/zolana/prover/server v0.0.0-20261012183753-51fb595db7e2

// Match Zolana's extractor fork; dependency-module replacements are not inherited.
replace github.com/reilabs/gnark-lean-extractor/v3 => github.com/Lightprotocol/gnark-lean-extractor/v3 v3.0.0-20250920122823-aa0219463107
