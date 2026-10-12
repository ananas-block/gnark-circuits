# AES-256-CTR and the P-256 ECIES envelope

Notes on [`aes`](aes), [`kdf.go`](kdf.go) and [`ecies.go`](ecies.go), which were
extracted from the Zolana prover (`prover/server/circuits/verifiable-encryption`, commit
`18ac9ffa1`). All counts are BN254 R1CS from gnark v0.16.3. Proving times are in
[`../BENCHMARKS.md`](../BENCHMARKS.md).

## Entry points

| API | Use |
| --- | --- |
| `aes.NewCipher(api, key).CTREncrypt(nonce, plaintext)` | AES-256-CTR on the spread-lane lookup path. Lookup tables are shared across ciphers through the compiler's key-value store. |
| `encryption.KeySchedule` | Zolana's Poseidon key schedule, from a field element to a 32-byte key and a 12-byte nonce. |
| `encryption.Envelope{...}.Seal(api)` | P-256 key agreement, Poseidon transcript, key schedule and AES-256-CTR. |

The `aes` package is copied from Zolana's `verifiable-encryption/aes` (zolana
commit `51fb595db`) without its Lean-extraction hooks; the circuit is unchanged.
This repository keeps only the lookup path. The pure-R1CS AES, the legacy
T-table AES, the gnark std envelope baseline (`StdEnvelope`, `LegacyKeySchedule`)
and the counter modes were not carried over; their sections below are historical
measurements.

The counter follows the GCM convention: `J0 = nonce || 00000001`, and block `b`
(zero-based) encrypts `nonce || be32(b + 2)`. A host gets the same keystream from
Go's `cipher.NewCTR(aes, nonce || 00 00 00 02)`.

## Spread-lane AES (lookup path)

AES is XOR-heavy, and XOR is not native to the field. The lookup path stores every
table word in *spread* form. Bit `l` of a 32-bit word becomes the digit at position
`l` in base 6: `spread(w) = sum_l bit_l(w) * 6^l`. An inner-round column adds four
spread T-table words (`T0[a] + T1[b] + T2[c] + T3[d]`) to the spread round-key word.
That is an ordinary field sum of five terms. Each digit is at most 5 < 6, so no digit
carries. The XOR of the five bits is the parity of each digit.

- **Tables (one BSB22 commitment for all of them).** The substitution table has
  1,280 rows: four 256-row T-table regions plus one 256-row spread S-box region.
  The byte-spread table has 256 rows. The chunk-parity table has 1,296 rows, mapping
  a 4-lane base-6 chunk `c < 6^4` to its 4-bit parity nibble.
- **Lane split.** A hint splits the column sum into 8 chunks of 4 lanes. One row
  checks the recomposition `sum = sum_k chunk_k * 1296^k`. Each chunk is looked up in
  the 1,296-row table, which range-checks the chunk and returns its nibble. Each output
  byte is `nibble_lo + 16 * nibble_hi`, which is linear. This gives **25 constraints
  per column**: 4 substitution lookups, 8 chunk lookups, the recomposition and the
  lookup bookkeeping. The figure was measured as the marginal cost of 100 extra
  columns: 25.02.
- **Fixed cost.** Tables plus one query cost 3,835 constraints. Adding the AES-256
  key expansion brings this to 5,302: 52 words, with S-box words taken from the spread
  S-box region and XORs on the same lane split.
- **Per block.** The first block costs 1,528 constraints: round 0 on the nonce,
  round 1, and the cached first-round columns. Each further block costs about 1,374:
  12 middle rounds × 4 columns × 25, one round-1 column, plaintext spreads and the
  final round. The counter's high bytes are constant across blocks, so round 0 and
  columns 1 to 3 of round 1 are computed once (`ctrStream.refreshFirstRound`). Only
  column 0, which reads counter byte 15, is recomputed per block. The final round
  folds the spread plaintext byte into the same sum, so the ciphertext comes out of
  one lane split, and the keystream is never a separate variable.
- **Totals.** 16 B: 6,830. 40 B: 9,502. 48 B: 9,577. 72 B: 12,250.

### Variants measured and rejected

| AES-256-CTR | 16 B | 48 B |
| --- | ---: | ---: |
| Legacy T-table lookups with `ToBinary` XOR (`CTREncrypt`) | 25,679 | 71,157 |
| Bit-decomposed round keys | 20,203 | 49,451 |
| Spread base-8 lanes, `ToBinary` split | 14,098 | 25,364 |
| Spread base-6 lanes, 2-lane chunks (36-row table) | 7,349 | 11,803 |
| **Spread base-6 lanes, 4-lane chunks (1,296-row table)** | **6,830** | **9,577** |

- **Base 8 with `ToBinary`.** A 3-bit lane also absorbs a sum of five bits without
  carry, so the parity is the low bit of each lane after a 96-bit `ToBinary` per
  column. That costs about 97 rows per column against 25 for the lookup split. Base 6
  is the smallest base that holds the digit 5. It keeps chunk tables small
  (6^4 = 1,296 against 8^4 = 4,096).
- **2 versus 4 lanes per chunk.** A 2-lane chunk table has only 36 rows, but it needs
  16 chunk lookups per column instead of 8. The extra queries cost more than the
  1,260 table rows saved: +519 at 16 B and +2,226 at 48 B. Five or more lanes
  (7,776 rows) would grow the fixed cost faster than the per-column saving.

## Pure-R1CS AES (no lookups)

> Not part of this repository; kept as a historical measurement.

`NewAESGadgetWithLookups(api, false)` uses no table and no commitment, so it gives a
plain Groth16 verifying key. It costs 25,796 constraints at 16 B and 62,404 at 48 B.

- **S-box as a hinted GF(2^8) inverse, 64 rows.** A hint supplies the eight S-box
  output bits `s`. The circuit derives the inverse `y` from `s` with the inverse affine
  map, one XOR3 row per bit, and proves `x * y = 1` in GF(2^8), or `y = 0` when
  `x = 0`. The polynomial product `x(t) * y(t)` is computed by evaluating both at 15
  integer points (0, ±1, ..., ±7) and interpolating with a constant inverse
  Vandermonde matrix: 15 multiplications. Karatsuba needs 27 and schoolbook needs 64.
  Reduction modulo `x^8 + x^4 + x^3 + x + 1` is linear over the integer coefficients.
  Each reduced coefficient must have parity 0 (or 1 for the constant term when
  `x != 0`), which is checked with a short bit decomposition of half the coefficient.
  The S-box costs 64 rows, excluding the 9-row input decomposition and the output
  equality (74 in total as measured).
- **Alternatives.** Hinting the inverse instead of the S-box bits costs 82 rows with
  the linear layer fused or with the output bits settled. A one-hot mux (64 flags over
  the low 6 bits, with the top 2 bits as selectors) costs **87** rows. Key expansion
  costs 5,249 constraints with the default method and 6,882 with the mux. The test
  suite asserts that the default is the cheapest method.
- **Single-row XOR3.** For bits `a, b, c`, the gadget computes
  `r = (6a + 6b - 24c) / (a + b - 4c + 1)` with one `DivUnchecked` row, then
  `a ⊕ b ⊕ c = r - 2a - 2b - 7c`. The denominator is never zero on bits. Longer XORs
  use XOR3 chains, or a hinted parity with a short range proof when that is cheaper.
- **Symbolic linear layer.** Bytes are carried as XOR forms: sorted sets of bit ids
  plus a constant flip. ShiftRows, MixColumns, AddRoundKey and the S-box affine map are
  operations on these forms. A form becomes a real variable ("settled") only when an
  S-box needs its bits. Settled forms are memoised.
- **Unmaterialized keystream.** In CTR mode the plaintext byte is XORed into the
  final-round form, and only the ciphertext bits are settled. Counter bytes are
  constants, so they never cost rows.

## Key schedule

`KeySchedule(api, s, info)` is Zolana's key schedule
(`prover/server/circuits/verifiable-encryption/poseidon_kdf.go`), which the
Rust host KDF in `sdk-libs/keypair/src/encryption.rs` mirrors byte for byte.
It turns a field element `s` into an AES-256 key and a CTR nonce. `info` is a
compile-time label of at most 434 bytes; its final 31-byte chunk must not start
with zero, so labels of different lengths cannot pack to the same field
elements. The Zolana merge uses `MergeKdfInfo = "TMEC"`.

Host derivation (BN254 scalar field `r`, Light/circom Poseidon):

```
info_k = int_be(info[31k : 31k+31])        # 31-byte big-endian chunks
silo   = Poseidon(0x544d5349, s, info_0, info_1, ...)
lo     = be32(Poseidon(0x544d534b, silo))
hi     = be32(Poseidon(0x544d534c, silo))
nonce  = be32(Poseidon(0x544d534e, silo))[20:32]
key    = hi[16:32] || lo[16:32]
```

Here `be32(v)` is the 32-byte big-endian encoding of the canonical integer
`v < r`. Each Poseidon output is decomposed with a 256-bit `ToBinary`, which
gnark constrains to the canonical representation, so no hint or separate
canonicity argument is needed.

## ECIES envelope

`Envelope{SecretTag, KdfInfo, EphemeralSk, RecipientPk, Plaintext}.Seal(api)`:

1. `p256.AgreeKey(api, ephemeralSk, recipientPk)`. This checks that
   `recipientPk` is a canonical uncompressed point on the curve
   (`0x04 || X || Y`). It computes `E = sk·G` and the shared point `sk·R`.
2. Packing, where `compressed(P) = (0x02 | y_parity) || be32(x)` is 33 bytes:
   - `RecipientLo = int_be(c_R[0:31])`, `RecipientHi = int_be(c_R[31:33])` (16 bits)
   - `EphemeralLo = int_be(c_E[0:31])`, `EphemeralHi = int_be(c_E[31:33])`
   - `SharedLo = int_be(x_shared[0:31])`, `SharedHi = x_shared[31]`
3. Transcript: `s = Poseidon(int_be(SecretTag), SharedLo, SharedHi, EphemeralLo,
   EphemeralHi, RecipientLo, RecipientHi)`. The merge uses `MergeSecretTag = "TMES"`.
4. `key, nonce = KeySchedule(s, KdfInfo)`, then
   `ciphertext = AES-256-CTR(key, nonce, plaintext)` with the counter above.

`Sealed` returns the four key packings, `SharedSecret` and the ciphertext bytes. The
caller must bind them in its public input: at least the recipient packing, the
ephemeral packing and the ciphertext. The gadget does not range-check plaintext
bytes, so the caller ties them to its own decomposition. The Zolana merge packs
`[RecipientLo, EphemeralLo, RecipientHi·2^(8(2+h)) + EphemeralHi·2^(8h) + ct[0:h],
then ct[h:] in 31-byte chunks]` with `h = min(27, len(ct))`. A host decrypts with
`crypto/ecdh` (recipient secret × ephemeral point), the same packing and Poseidon
calls, and `crypto/aes` CTR. `ecies_test.go` runs this mirror. It also rejects a tampered
ciphertext and a foreign recipient key, and asserts one BSB22 commitment.

Cost (gnark v0.16.4, `go run ./cmd/benchmark`): key agreement 25,359 + AES-CTR
6,830 + 2,866 for the transcript and key schedule (one 7-input Poseidon, four
Poseidon calls and three 256-bit decompositions) gives 35,055 at 16 B. At 40 B
the total is 37,727 and at 48 B it is 37,802.

### gnark std baseline

> Not part of this repository; kept as a historical measurement.

`StdEnvelope{SecretTag, KdfInfo, EphemeralSk, RecipientPk, Plaintext}.Seal(api)`
is the same pipeline with the key agreement and the KDF replaced by what
existed before the vendored arithmetic: the key agreement is
[`p256/std`](../p256/std/keyagreement.go) on `sw_emulated` with the
two-assertion fake-GLV fix (see [`p256/FINDINGS.md`](../p256/FINDINGS.md)),
the KDF is `LegacyKeySchedule` (the custom-ring `KeySchedule`: silo, two key
halves and the nonce from four Poseidon calls, each output decomposed with a
256-bit `ToBinary`, about 2,490 constraints against 745 for the stream KDF,
kept because it needs no hints and no canonicity argument of its own), and
the cipher is the spread-lane AES, the same gadget the vendored envelope uses.
With the T-table `aes.CTREncrypt` instead, at about 22.6k per block, the std
envelope measured 174,364 / 219,562 / 219,842 at 16 / 40 / 48 B. The
transcript, the packing and the `Sealed` outputs are identical, so a host
mirror only swaps the KDF; `ecies_std_test.go` runs it, rejects a tampered
ciphertext and a foreign recipient, replays the report's forgery through the
whole envelope and asserts one commitment.

| Envelope | 16 B | 40 B | 48 B |
| --- | ---: | ---: | ---: |
| vendored, lookup | 38,387 | 41,059 | 41,134 |
| vendored, no lookup | 163,606 | 199,530 | 200,214 |
| gnark std key agreement, legacy KDF, spread AES | 155,515 | 158,187 | 158,262 |

The std row's key agreement is 145,819 of that, so the whole gap to the
vendored envelope is the field arithmetic: 4x at one block, and on wires
(239,468 against about 50k) about 5x. The 40 B rows are the merge-mask size.
`algopts.WithIncompleteArithmetic()` would take gnark's `ScalarMul` to about
92.5k but is not used: the ladder's incomplete additions divide by x2 - x1
unchecked, its operands include the hinted result, and the distinct-x guards
the vendored ladder adds cannot be added from outside gnark's API.

## Comparison with the counter modes

> Not part of this repository; kept as a historical measurement.

From `BENCHMARKS.md`, x1, BN254 Groth16. The counter modes encrypt the 40-byte merge
mask (elements of 8, 31 and 1 bytes) under a field-element key. AES encrypts raw
bytes under a 32-byte key and a 12-byte nonce.

| Keystream | Plaintext | Commitment | Constraints |
| --- | --- | --- | ---: |
| Poseidon (`FieldCtr`) | 3 elements | no | 876 |
| BLAKE3 lookup, `ShortInputs` | 40 B | yes | 5,206 |
| BLAKE3 lookup, canonical | 40 B | yes | 5,342 |
| AES-256-CTR spread lookup | 16 B | yes | 6,830 |
| AES-256-CTR spread lookup | 40 B | yes | 9,502 |
| AES-256-CTR spread lookup | 48 B | yes | 9,577 |
| BLAKE3 pure | 40 B | no | 16,340 |
| AES-256-CTR no lookup | 16 B | no | 25,796 |
| AES-256-CTR legacy T-table | 16 B | yes | 25,679 |
| SHA-256 counter mode | 40 B | no | 27,213 |
| AES-256-CTR no lookup | 40 B | no | 61,720 |
| AES-256-CTR legacy T-table | 48 B | yes | 71,157 |

Poseidon remains the cheapest by an order of magnitude, but a recipient needs a
Poseidon implementation. AES with lookups costs about 1.8x BLAKE3 with lookups on the
merge mask. Unlike BLAKE3, every client platform has a native AES. The fixed table
cost (about 3.8k) dominates one block, so ten instances share it: x10 at 16 B costs
33,819, against 68,300 for ten separate circuits. Without lookups, AES is the most
expensive option beyond one block. Use it only where the verifier cannot handle a
BSB22 commitment.
