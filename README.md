# gnark-circuits

Ed25519 signature verification, X25519 key agreement and ECIES gadgets for gnark on BN254,
with measured Groth16 costs.

## Packages

- [`ed25519`](ed25519): Solana Ed25519 precompile signature verification with in-circuit SHA-512, six 43-bit limbs, lookup range checks, constrained torsion splits and a 127-bit joint checker; 50,648 constraints including SHA-512 for a 32-byte message (gnark v0.16.4).
- [`x25519`](x25519): RFC 7748 ECDH and key agreement, with scalar clamping, curve/twist inputs, canonical output and all-zero secret rejection. Uses BSB22 lookups.
- [`encryption`](encryption): an X25519 ECIES envelope (`Envelope.Seal`): key agreement, a Poseidon transcript, a Poseidon key schedule and AES-256-CTR on spread-lane lookup tables ([`encryption/aes`](encryption/aes)); a host reproduces it with `crypto/ecdh` and `crypto/aes`. Design and costs in [`encryption/FINDINGS.md`](encryption/FINDINGS.md).
- [`hasher`](hasher): the SHA-512 gadget used by Ed25519.
- [`internal/emfield`](internal/emfield): shared non-native field arithmetic used by Ed25519, X25519 and SHA-512.
- [`internal/lookup`](internal/lookup), [`internal/r1c`](internal/r1c): the shared BSB22 lookup table and R1CS helpers.
- [`BENCHMARKS.md`](BENCHMARKS.md): Groth16 constraint counts and proving times, one and ten instances per circuit; regenerate with `go run ./cmd/benchmark`, or measure single rows with `-only <substring> -out <file>`.

Ed25519 and X25519 use the Edwards and Montgomery forms of the same
Curve25519 field. The envelope accepts a 32-byte X25519 recipient public key
and derives a 32-byte ephemeral public key.

## Tests

Requires Go 1.27.1 and access to the private module dependencies. From the
repository root:

```sh
GOPRIVATE='github.com/helius-labs/*' go mod download
GOPRIVATE='github.com/helius-labs/*' go test ./...
go vet ./...
```

The module pins gnark `v0.16.4`. Dependency versions and replacements are
configured in `go.mod`. The Ed25519 test vectors can be regenerated with the
Rust oracle in
[`ed25519/testdata`](ed25519/testdata/README.md).
