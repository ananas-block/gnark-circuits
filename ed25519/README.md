# Ed25519 verification

`Verify` asserts the Ed25519 signature predicate used by Solana's [Ed25519 precompile](https://github.com/anza-xyz/agave/blob/master/precompiles/src/ed25519.rs), pinned to `ed25519-dalek 1.0.1` and `curve25519-dalek 3.2.0`. It computes `h=SHA-512(R||A||M) mod L` inside the circuit and checks the complete signature equation. The input message length is fixed when compiling; 32-byte messages are the benchmark target.

```go
type Circuit struct {
    PublicKey [32]frontend.Variable `gnark:",public"`
    Message   [32]frontend.Variable `gnark:",public"`
    Signature [64]frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
    ed25519.Verify(api, ed25519.Inputs{
        PublicKey: c.PublicKey,
        Signature: c.Signature,
        Message: c.Message[:],
    })
    return nil
}
```

Public keys and R use compressed Edwards-y encoding; S is little endian and strictly less than L. The gadget rejects malformed and small-order points, accepts mixed torsion, and preserves the precompile's noncanonical point-encoding behavior. Both original encodings enter SHA-512. The surrounding circuit chooses public inputs; the example exposes the key and message while keeping the signature private.

## Arithmetic

The field uses six 43-bit limbs and eleven-bit lookup pieces. Three complete doublings prove each split `P=[8]W+T`, giving a prime component and a constrained eight-torsion selector. A separate equation checks the torsion contributions.

Extended Euclid supplies 127-bit u,v with `u*h=v mod L` and u nonzero. The prime equation becomes `[u]R0+[v]A0=[u*S]B`. A signed radix-four joint ladder uses a prover-selected offset `J=jB`, with j in 1..256; fewer than 256 choices can cause an exceptional intermediate, so every valid signature has a usable offset. Exact native-field alias guards and a final cubic curve check bind the lazy arithmetic. The fixed-base side uses signed eight-bit windows, positive-magnitude tables and packed constant selection. Host witness multiplication uses complete extended coordinates and one final inversion.

This reaches 29,786 constraints for the arithmetic and encoding checks, compared with current P-256 ECDSA at 30,164 and its original 31,013. Complete 32-byte-message verification, including SHA-512, uses 50,678 constraints. P-256 with in-circuit SHA-256 for the same 32-byte message uses 44,258 constraints; complete Ed25519 is 14.5% larger. Both single-instance circuits use a 65,536-point Groth16 domain. The original P-256 row takes an already computed digest. Actual Groth16 proving measurements and batch costs are in [BENCHMARKS.md](BENCHMARKS.md).

## Verification

```sh
go test ./ed25519 ./hasher ./internal/... ./p256/...
go vet ./...
go run ./cmd/benchmark -only Ed25519 -runs 5
```

The tests compare 914 CCTV cases against the exact Solana library, 320 supplied-challenge cases across all torsion classes, scalar boundaries, 69 native-field alias cases, malformed inputs, forged hints, and a coincident-chord attack. SHA tests cover nine message lengths and alternate slice carries; host arithmetic is checked against independent affine formulas on 1,076 cases. [Audit notes](../audit/ed25519/statement.md) contain the statement, bounds, polynomial identities, coverage and verifier obligations. This uses BN254 Groth16 with the commitment-aware BSB22 verifier, as the existing lookup gadgets do.

The field and table choices were checked with an Ed25519-specific sweep of 50 feasible layout/lookup-width variants and 62 baseline window/packing variants. The current choices were retuned after the projected field changes. They are the best measured configurations here; this does not claim a global optimum. Local experiment and timing records are in [docs/perf-loop](../../docs/perf-loop/state.md).
