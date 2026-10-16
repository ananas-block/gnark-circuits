# encryption

An X25519 ECIES envelope for gnark over BN254, using a Poseidon KDF and AES-256-CTR.

| File | Contents |
| --- | --- |
| `ecies.go` | `Envelope.Seal`: X25519 key agreement (`x25519.AgreeKey`), a Poseidon transcript over the packed keys and shared secret, the Poseidon key schedule and AES-256-CTR. |
| `kdf.go` | `KeySchedule`: the Poseidon key schedule. Four Poseidon calls (silo, two key halves, nonce) derive a 32-byte AES key and a 12-byte nonce from the shared secret. |
| [`aes`](aes) | AES-256-CTR on spread-lane lookup tables (one BSB22 commitment shared by every cipher in a circuit). |

A host reproduces the envelope with Go's `crypto/ecdh` and `crypto/aes`; the
tests check the circuit against that host implementation.

Design, KDF derivation and costs are in [`FINDINGS.md`](FINDINGS.md).

Recipient public keys are 32-byte RFC 7748 encodings. The transcript binds
the original recipient bytes and canonical ephemeral/shared encodings; each
is packed as a 31-byte big-endian chunk and one final byte. This changes
the envelope format from the earlier P-256 version.
