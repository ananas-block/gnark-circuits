# Ed25519 historical benchmarks

These historical measurements predate the stricter canonical prime-subgroup and
curve checks. Current 32-byte-message verification uses 58,232 constraints.

These measurements predate the X25519 migration; P-256 is no longer included.
The current benchmark report is [../BENCHMARKS.md](../BENCHMARKS.md).

Measured on Apple M5 Pro with Go 1.27.1, gnark 0.16.3 and BN254 Groth16,
working tree based on fdce0f9. Final benchmark rows ran sequentially after
experiment CPU work stopped. Times are median of five Prove calls, excluding
compilation, setup and witness creation; one proof verifies per circuit.
x10 uses ten distinct instances sharing lookup tables and one BSB22 commitment.

Ed25519 and P-256 + SHA-256 expose the key and 32-byte message publicly with
private signatures. The raw P-256 row consumes a digest and exposes the
signer's x coordinate. Ed25519 computes SHA-512(R || A || M) in the circuit.
The P-256 + SHA-256 row was measured before this repository was split out;
its SHA-256 gadget is not included here, so that row cannot be reproduced.

| Circuit | BSB22 | Constraints x1 | Proving x1 (ms) | Constraints x10 | Proving x10 (ms) |
|---|---|---:|---:|---:|---:|
| Ed25519 verification + SHA-512, 32 B message (Solana) | yes | 50,678 | 214.1 | 461,641 | 1111.3 |
| P-256 ECDSA verification, lookup (VerifyECDSA) | yes | 30,164 | 105.7 | 273,061 | 800.9 |
| P-256 ECDSA verification + SHA-256, 32 B message | yes | 44,258 | 126.4 | 414,001 | 873.7 |

| Test-only arithmetic/encoding boundary | Constraints | Proving median (ms), five runs |
|---|---:|---:|
| Ed25519, precomputed 64-byte digest | 29,786 | 96.08 |
| P-256 ECDSA, precomputed digest | 30,164 | 105.7 |

Ed25519 arithmetic has **1.25% fewer** constraints than the current P-256
implementation and **3.96% fewer** than the original 31,013. Both arithmetic
circuits use a 32,768-point domain. The Ed25519 test boundary has public key
bytes and private signature/digest; the public Verify always hashes in circuit.

With required hashes, full Ed25519 has **14.5% more** constraints singly and
**11.5% more** for ten than P-256 + SHA-256. Both single full verifiers use a
65,536-point domain and both x10 verifiers a 524,288-point domain. Full proof
times remain higher: 214.1 vs 126.4ms and 1111.3 vs 873.7ms for ten. Arithmetic
meets the original comparison target; this does not claim a faster complete
Ed25519 verifier. Single-machine medians are observations, not timing guarantees.

## Arithmetic optimizations

Aligned CRT products, shared native/low carry projections, balanced carry
coefficients, correlated lazy bounds and scalar extraction reduce the
combined full count from 50,964 to 50,678 and arithmetic from 30,072 to 29,786.
Individual savings overlap.

Fifty feasible limb/lookup-width variants and 62 baseline table/window variants
were measured. The best tested choices remain 6×43 limbs, piece 11, constant X2/Y3
and joint 2. Final-kernel retuning favors window 8; the bigger tables add 8,779
coefficients but remove 358 internal variables. This is an empirical choice,
not a global optimum proof.

A separate controlled comparison uses identical full 32-byte inputs,
GOMAXPROCS 8, three warmups and 21 timed proofs per run, each verified outside
timing. Sequential baseline/candidate7/baseline/candidate7/candidate8/candidate7/
candidate8 runs had pooled medians 286.616/281.390/272.703ms respectively.
No other circuit jobs were observed at run starts; other host load remains
uncontrolled. These timings use different settings from the five-run table
and must not be combined with it. Raw samples, binary hashes, source snapshots,
rejected variants and commands are in the local ignored
[performance records](../../docs/perf-loop/state.md).

Standalone SHA-512:

| Circuit | BSB22 | Constraints x1 | Proving x1 (ms) | Constraints x10 | Proving x10 (ms) |
|---|---|---:|---:|---:|---:|
| SHA-512 lookup, 64 B message (one compression) | yes | 20,724 | 124.2 | 193,701 | 516.6 |
| SHA-512 lookup, 128 B message (two compressions) | yes | 35,588 | 235.3 | 342,283 | 861.2 |


Reproduce the final tables from the repository root:

```sh
go test ./...
go vet ./...
go test ./ed25519 -run '^$' -bench '^BenchmarkArithmeticProve$' -benchtime=5x -count=1
go run ./cmd/benchmark -only Ed25519 -runs 5 -out /tmp/ed25519.md
```

Final signature snapshots:

- 2026-10-11 21:48 UTC — fdce0f9+dirty — Apple M5 Pro — gnark v0.16.3
- 2026-10-11 21:49 UTC — fdce0f9+dirty — Apple M5 Pro — gnark v0.16.3
- 2026-10-11 21:50 UTC — fdce0f9+dirty — Apple M5 Pro — gnark v0.16.3
