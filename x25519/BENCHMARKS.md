# X25519 benchmark measurements

See the current [repository report](../BENCHMARKS.md) for this branch.

BN254 R1CS / Groth16 measurements using `cmd/benchmark`, five proofs
per circuit. Times are median `groth16.Prove` wall times, including circuit
solving; compilation, setup and witness construction are excluded. One proof
per circuit is verified. x10 uses ten distinct instances and shares lookup
tables. All campaign builds and tests were stopped during measurements.
These are timing samples; constraint counts are deterministic.

X25519 rows: 2026-10-15, after the
shared-ladder refactor that moved the affine arithmetic to `internal/shortw`.
Apple M5 Pro — gnark v0.16.3.

## Raw ECDH

ECDH rows expose only the 32-byte shared secret; scalar and peer are private.

| Circuit | BSB22 | Constraints x1 | Proving x1 (ms) | Constraints x10 | Proving x10 (ms) |
|---|---|---:|---:|---:|---:|
| X25519 ECDH, lookup (ECDH) | yes | 21,221 | 88.6 | 199,740 | 585.9 |

## Full key agreement

AgreeKey rows derive the ephemeral public key and return six public fields:
packed recipient key, ephemeral key, and shared secret. X25519 accepts a
32-byte peer encoding and uses first-31-byte / final-byte big-endian chunk
packing. These measurements include no hash or KDF.

| Circuit | BSB22 | Constraints x1 | Proving x1 (ms) | Constraints x10 | Proving x10 (ms) |
|---|---|---:|---:|---:|---:|
| X25519 key agreement, lookup (AgreeKey) | yes | 25,914 | 99.7 | 246,663 | 688.8 |

## Reproduce

From the repository root:

```sh
go run ./cmd/benchmark -only 'ECDH,' -runs 5 -out /tmp/raw-ecdh.md
go run ./cmd/benchmark -only 'X25519 key agreement' -runs 5 -out /tmp/key-agreement.md
```

The lookup layouts favor single-instance X25519 cost. Larger range tables
can amortize better across ten instances; the published default and both
batch sizes are measured here. See [README.md](README.md) for the statement,
optimizations, packing and validation.
