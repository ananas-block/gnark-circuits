# encryption

An X25519 ECIES envelope for gnark over BN254, using Zolana's Poseidon KDF and AES gadget.

| File | Contents |
| --- | --- |
| `ecies.go` | `Envelope.Seal`: X25519 key agreement (`x25519.AgreeKey`), a Poseidon transcript over the packed keys and shared secret, Zolana's key schedule and AES-256-CTR. |
| `kdf.go` | `KeySchedule`: Zolana's key schedule. Four Poseidon calls (silo, two key halves, nonce) derive a 32-byte AES key and a 12-byte nonce from the shared secret; the Rust SDK mirrors it. |
| [`aes`](aes) | AES-256-CTR on spread-lane lookup tables (one BSB22 commitment shared by every cipher in a circuit), copied from Zolana's `verifiable-encryption/aes` without its Lean-extraction hooks. |

A host reproduces the envelope with Go's `crypto/ecdh` and `crypto/aes`; the
tests check the circuit against that host implementation. Poseidon is Zolana's
gadget (`zolana/prover/circuits/gadget`), pinned through the module's `go.mod`.

Design, KDF derivation and costs are in [`FINDINGS.md`](FINDINGS.md).

Recipient public keys are 32-byte RFC 7748 encodings. The transcript binds
the original recipient bytes and canonical ephemeral/shared encodings; each
is packed as a 31-byte big-endian chunk and one final byte. This changes
the envelope format from the earlier P-256 version.
