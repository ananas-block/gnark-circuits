# encryption

A P-256 ECIES envelope for gnark over BN254, copied from the Zolana prover
(`prover/server/circuits/verifiable-encryption`).

| File | Contents |
| --- | --- |
| `ecies.go` | `Envelope.Seal`: P-256 key agreement (`p256.AgreeKey`), a Poseidon transcript over the packed keys and shared secret, Zolana's key schedule and AES-256-CTR. |
| `kdf.go` | `KeySchedule`: Zolana's key schedule. Four Poseidon calls (silo, two key halves, nonce) derive a 32-byte AES key and a 12-byte nonce from the shared secret; the Rust SDK mirrors it. |
| [`aes`](aes) | AES-256-CTR on spread-lane lookup tables (one BSB22 commitment shared by every cipher in a circuit), copied from Zolana's `verifiable-encryption/aes` without its Lean-extraction hooks. |

A host reproduces the envelope with Go's `crypto/ecdh` and `crypto/aes`; the
tests check the circuit against that host implementation. Poseidon is Zolana's
gadget (`zolana/prover/circuits/gadget`), pinned through the module's `go.mod`.

Design, KDF derivation and costs are in [`FINDINGS.md`](FINDINGS.md).
