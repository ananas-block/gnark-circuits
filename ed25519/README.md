# Ed25519 verification

`Verify` asserts a canonical prime-subgroup Ed25519 signature predicate. Both the public key and R must be canonically encoded nonidentity points in the prime subgroup. This is stricter than the Solana precompile predicate pinned in the test fixtures. It computes `h=SHA-512(R||A||M) mod L` inside the circuit and checks the complete signature equation. The input message length is fixed when compiling; 32-byte messages are the benchmark target.

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

Public keys and R use compressed Edwards-y encoding; S is little endian and strictly less than L. The gadget rejects malformed and small-order points, mixed torsion, and noncanonical point encodings. Both original encodings enter SHA-512. The surrounding circuit chooses public inputs; the example exposes the key and message while keeping the signature private.

## Arithmetic

The field uses six 43-bit limbs and eleven-bit lookup pieces. Three complete doublings prove each split `P=[8]W+T`, giving a prime component and a constrained eight-torsion selector. Production verification requires both torsion selectors to be zero and both decoded y coordinates to be canonical.

Extended Euclid supplies 127-bit u,v with `u*h=v mod L` and u nonzero. The prime equation becomes `[u]R0+[v]A0=[u*S]B`. A signed radix-four joint ladder uses a prover-selected offset `J=jB`, with j in 1..256; fewer than 256 choices can cause an exceptional intermediate, so every valid signature has a usable offset. Exact native-field alias guards, a coincident-chord tangent check, and curve-membership checks on coordinate conversions bind the lazy arithmetic. The fixed-base side uses signed eight-bit windows, positive-magnitude tables and packed constant selection. Host witness multiplication uses complete extended coordinates and one final inversion.

Complete 32-byte-message verification, including SHA-512, uses 58,232 constraints on gnark v0.16.4. Historical Groth16 proving measurements and batch costs, before the stricter checks, are in [../BENCHMARKS.md](../BENCHMARKS.md); [BENCHMARKS.md](BENCHMARKS.md) preserves earlier optimization measurements.

## Verification

```sh
go test ./ed25519 ./hasher ./internal/... ./x25519/...
go vet ./...
go run ./cmd/benchmark -only Ed25519 -runs 5
```

A test-only reference predicate compares 914 CCTV cases against the pinned Solana library. The production predicate additionally rejects torsion and encoding aliases, including cancelling-torsion signatures and forged exceptional conversion hints. Both predicates exercise 320 supplied-challenge cases across all torsion classes; other tests cover scalar boundaries, 69 native-field alias cases, malformed inputs, forged hints, and a coincident-chord attack. SHA tests cover nine message lengths and alternate slice carries; host arithmetic is checked against independent affine formulas on 1,076 cases. This uses BN254 Groth16 with the commitment-aware BSB22 verifier, as the existing lookup gadgets do.

The field and table choices were checked with an Ed25519-specific sweep of 50 feasible layout/lookup-width variants and 62 baseline window/packing variants. The choices were retuned after the projected field changes, before these stricter checks; no layout retuning has been performed for the stricter predicate. Local experiment and timing records are in [docs/perf-loop](../../docs/perf-loop/state.md).
