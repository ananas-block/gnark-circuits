# gnark-circuits

Signature verification, P-256 key agreement and ECIES gadgets for gnark on BN254,
with measured Groth16 costs.

## Packages

- [`ed25519`](ed25519): Solana Ed25519 precompile signature verification with in-circuit SHA-512, six 43-bit limbs, lookup range checks, constrained torsion splits and a 127-bit joint checker; 50,648 constraints including SHA-512 for a 32-byte message (gnark v0.16.4). Audit notes are in [`audit/ed25519`](audit/ed25519/statement.md).
- [`p256`](p256): P-256 ECDSA verification (`VerifyECDSA`), plus ECDH and key agreement, on an 8x32-bit Solinas-fold field ([`p256/emfield`](p256/emfield)), on BSB22 lookup tables, with a fake-GLV ladder that rejects the gnark v0.16.3 forgery; design, sweeps and soundness notes in [`p256/FINDINGS.md`](p256/FINDINGS.md).
- [`encryption`](encryption): a P-256 ECIES envelope (`Envelope.Seal`): key agreement, a Poseidon transcript, Zolana's Poseidon key schedule and AES-256-CTR on spread-lane lookup tables ([`encryption/aes`](encryption/aes)); a host reproduces it with `crypto/ecdh` and `crypto/aes`. Design and costs in [`encryption/FINDINGS.md`](encryption/FINDINGS.md).
- [`hasher`](hasher): the SHA-512 gadget used by Ed25519. P-256 ECDSA takes an already computed message digest.
- [`internal/lookup`](internal/lookup), [`internal/r1c`](internal/r1c): the shared BSB22 lookup table and R1CS helpers.
- [`BENCHMARKS.md`](BENCHMARKS.md): Groth16 constraint counts and proving times, one and ten instances per circuit; regenerate with `go run ./cmd/benchmark`, or measure single rows with `-only <substring> -out <file>`.

## Tests

Requires Go 1.27.1 and access to the Zolana GitHub repository, whose Poseidon
gadget the ECIES envelope uses. From the repository root:

```sh
GOPRIVATE='github.com/helius-labs/*' go mod download
GOPRIVATE='github.com/helius-labs/*' go test ./...
go vet ./...
```

The module pins gnark `v0.16.4` and the gnark-crypto revision Zolana uses.
`go.mod` maps `zolana/prover` to Zolana commit `51fb595db` and keeps the Light
Protocol extractor fork its Poseidon gadget builds against. The Ed25519 test
vectors are regenerated with the Rust oracle in
[`ed25519/testdata`](ed25519/testdata/README.md).
