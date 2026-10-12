# Additional source reviews

Local circomlib: `/Users/jorrit/dev/experiments/circomlib`, clean revision
`35e54ea21da3e8762557234298dbb553c175ea8d`. Inspected EdDSA, BabyJub
addition/checking, Montgomery maps, fixed/variable scalar multiplication,
three/two-bit multiplexers and SHA-256. Its EdDSA uses native BabyJub and
Pedersen; those signature parameters are distinct from the requested Solana
Ed25519 predicate. We derived adaptations for Edwards25519 and measured
them under the existing foreign-field constraints.

Adopted: factored addition numerators, validation through reduced xy and
(xy)², cached constant-base dxy in parity correction, and shared monomial
selectors followed by inclusion-exclusion. These save 408 core rows. Full
beta/gamma/tau factoring cost 249 additional rows and was rejected. Signed
seven-bit fixed windows retain 37 selections; the three-bit Circom windows
would need 85. The experiments and source hashes are in circom-experiment.json.

Also inspected the local Picus Ed25519 and SHA-512 sources. Ed25519 uses
four extended coordinates with 3×85-bit chunks and two 255-bit ladders;
SHA-512 uses bitwise 64-lane sigma/choice/majority and separate T1/T2 and
round additions. The existing short joint checker, lazy affine coordinates,
lookup XORs and fused additions avoid those operations. These were used for
structural comparison, not as an acceptance oracle or measured benchmark.

[Solana ECVRF](https://github.com/blueshift-gg/solana-ecvrf), fetched revision
`ff22e7914f8a26f061638bfd4bfaf26742e9f1a3`: inspected lib.rs, curve.rs,
scalar.rs, sha512.rs, syscalls.rs and tests.rs. Group/SHA operations use
Solana syscalls, with dalek/sha2 host backends. No in-circuit arithmetic is
supplied. Its useful correctness observation is point negation: L−c
multiplication is not −c on mixed-torsion points. The gadget already negates
the prime point for its signed coefficient and separately checks the full
torsion equation. Its seven-entry small-order encoding table includes p and
p+1; our subgroup split and identity-rejecting maps already reject all such
encodings while preserving noncanonical-y behavior. Scalar canonicality and
original-byte hashing remain required.

The scalar comparison prompted an additional native-field gap check. For
reduced x<B<q and q+m>=2B, m−1−x has a native representative below B exactly
when x<m. Negative gaps wrap to at least q+m−B>=B. Static inequalities guard
the shortcut; larger foreign moduli retain the split-limb fallback. This
saves 8 rows for S/h and has dedicated boundary/fallback tests.

## Zcash and VM implementations

These are optimization source reviews, not security audits of the external
projects. All repository links below pin the inspected revision. Source
digests are recorded in `zkvm-source-hashes.json` and
`additional-source-hashes.json`; `zkvm-review.json` has the detailed file list.
AIR rows and native custom gates are not counted as BN254 R1CS constraints.

| Project and inspected implementation | Application to this gadget |
|---|---|
| [Zcash Halo2 fixed multiplication](https://github.com/zcash/halo2/blob/2d54aaf07c8135d0ce54313048999b4002b4cfbf/halo2_gadgets/src/ecc/chip/mul_fixed.rs), variable multiplication, constants and incomplete addition | Native Pallas uses three-bit windows and an auxiliary square-root discriminator. The discriminator contradicts a table containing both P and −P. Sign separation suggested selecting only positive magnitudes, then negating packed Montgomery y: independently tested and adopted, saving 252 constraints. This does not implement Halo2's discriminator. |
| [Sapling complete Edwards arithmetic](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs) and [Orchard fixed tables](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/constants/fixed_bases.rs) | Sapling's native Jubjub cross-product factoring agrees with the adopted Circom adaptation. Orchard supplies validated native three-bit tables. Their field and signature policies cannot replace Edwards25519/Solana. |
| [SP1 Edwards addition](https://github.com/succinctlabs/sp1/blob/bfc27de3931d90bceb32eb42b922b0165f7f7bf0/crates/core/machine/src/syscall/precompiles/edwards/ed_add.rs), decompression, field inner products and field operations | Addition fuses numerator products and proves quotient/carry equations with byte and sixteen-bit ranges. Our lazy CRT expressions already fuse those products. SP1 decompression's canonical-y requirement differs from the requested Solana predicate. Its small-field AIR costs do not imply a cheaper R1CS implementation. |
| [RISC Zero bigint elliptic curves](https://github.com/risc0/risc0/blob/3bbcd44d6459b9ef6ac0df3846dc9215514934e8/risc0/bigint2/src/ec/mod.rs), field wrappers, bigint circuit and accumulator witness generation | Field wrappers check canonical results at selected boundaries; bigint verification uses polynomial evaluation and bounded carry/memory arguments. Those backend-specific arguments need separate soundness and cost analysis before reuse. Our canonical boundary checks and constrained foreign certificates remain. The inspected digital-signature example is a passphrase/SHA-256 commitment, not an Ed25519 circuit. |
| [Miden Ed25519 precompile](https://github.com/0xMiden/miden-vm/blob/4016cf0532659da5368c97859ff869500c650ffb/crates/lib/core/asm/crypto/dsa/eddsa_25519_sha512.masm), host curve/order code and [SHA-512 AIR](https://github.com/0xMiden/miden-vm/blob/4016cf0532659da5368c97859ff869500c650ffb/crates/precompiles-air/src/hash/sha512/compression/program.rs) | Current pinned sources include Ed25519 and SHA-512. Negating the challenge in the 8L ring preserves mixed torsion; this supports our separate torsion equation. Shared XOR relations corroborate our existing parity-only choice/majority implementation. Host projective multiplication suggested the adopted extended-coordinate witness optimization. Miden's canonical point policy and Goldilocks-specific word splitting are not substituted. |
| [Lighter Schnorr circuit](https://github.com/elliottech/lighter-prover/blob/579f3d15ce54096d2ed0305747312a42d2e68d84/circuit/src/eddsa/schnorr.rs), affine operations and AIR constraints | Uses ECgFp5 over a Goldilocks extension and Poseidon2, not Ed25519/SHA-512. It combines fixed and variable windows and proves rational operations with denominator inverses and exceptional-case branches. Joint multiplication is already used here; switching its curve/hash would change the statement. Its batch STARK wrapper does not provide a direct gnark gadget cost. |
| [Polygon Hermez ZisK arithmetic equations](https://github.com/0xPolygonHermez/zisk/blob/1e22630bb7e143c30705a1603ed87cfd3da8c6ec/precompiles/arith_eq/pil/arith_eq.pil), generators and [proofman lookup components](https://github.com/0xPolygonHermez/pil2-proofman/blob/eda04742b64abe0e5322a8231f0155438ffb62fe/pil2-components/lib/std/pil/std_lookup.pil) | Generated quotient/carry certificates and range/lookup buses reinforce the current bound-checking discipline. Their sixteen-bit convolution/custom gates have a different cost model. The complete pinned ZisK tree has no dedicated Ed25519/SHA-512 named path; the inspected hash accelerator is SHA-256. Proofman is separately pinned, not claimed to be ZisK's exact released dependency. |
| [blst multiscalar multiplication](https://github.com/supranational/blst/blob/4f72b303888fd02d402a786eeb3d35ac38263ac2/src/multi_scalar.c), point operations and reciprocals | Native BLS12-381 code shares an inversion across affine conversions and stores positive window magnitudes with a separate sign. These corroborate the adopted sign selector and shared host inversions. Jacobian arithmetic and constant-time assembly performance do not establish foreign-field circuit savings. No blst dependency was added. |

The magnitude experiment records `30,324 → 30,072` arithmetic constraints and
`53,189 → 52,937` full constraints in `signed-magnitude-experiment.json`.
The host experiment uses complete extended Edwards formulas with one final
inversion, and one shared inverse for both affine addition denominators.
It retains unreduced scalars so [L]P still reveals torsion. Independent
affine references cover 1,076 cases, including all torsion classes and
malformed hint inputs. The microbenchmark improves scalar multiplication;
single-proof timing did not consistently improve. See
`host-arithmetic-experiment.json` and the final end-to-end benchmark report.

## Ethereum Research articles

Article URLs, retrieval dates and JSON digests are in
`ethresearch-source-hashes.json`. These are source-informed dispositions;
historical benchmark figures are not used as current comparison baselines.

| Article | Disposition |
|---|---|
| [Fake GLV](https://ethresear.ch/t/fake-glv-you-dont-need-an-efficient-endomorphism-to-implement-glv-like-scalar-multiplication-in-snark-circuits/20394) | Half-GCD supplies a short rational scalar relation. Its cancellation argument assumes a prime-order subgroup and a nonzero multiplier. Our constrained subgroup split, nonzero u and separate torsion equation supply those conditions for Solana inputs. Signed coefficients negate points rather than being interpreted modulo the native proof field. The four-dimensional extension discussed in the replies additionally needs an efficient endomorphism; none is introduced here. |
| [Fast linear combinations](https://ethresear.ch/t/simple-guide-to-fast-linear-combinations-aka-multiexponentiations/7238) | Sharing doublings and subset sums supports joint multiplication rather than separate ladders. Our two-base checker uses a constrained joint table and fused radix-four steps. Large-N subset heuristics do not remove the need to verify each signature and hash in the x10 benchmark. |
| [Precomputation methods](https://ethresear.ch/t/surveying-precomputation-methods-in-cryptography-request-for-help/8606) | Hinted inverses/roots can be verified by multiplication identities, and affine arithmetic can be attractive inside circuits. This matches the current constrained hints and lazy affine circuit. Host arithmetic separately benefits from projective coordinates; its CPU operation cost is different. |
| [Efficient ECDSA using Circom](https://ethresear.ch/t/efficient-ecdsa-signature-verification-using-circom/13629) | Moving public signature terms and multiplication caches outside the circuit can change verifier obligations and input binding. It cannot replace this self-contained Ed25519 predicate, where R, A and M must enter SHA-512 inside the circuit. Constant-base precomputation is already retained. |
| [Ed25519 proofs](https://ethresear.ch/t/verify-ed25519-signatures-cheaply-on-eth-using-zk-snarks/13139) and [IBC implementation](https://ethresear.ch/t/bringing-ibc-to-ethereum-using-zk-snarks/13634) | Electron Labs describes three 85-bit limbs exploiting 2^255−19. The related local Picus code was already inspected. Our six 43-bit limbs permit smaller lookup pieces and cheaper bounded certificates; measured experiments, rather than historical article counts, determine the layout. |
| [Native-field IBC alternative](https://ethresear.ch/t/approaches-to-ibc-light-clients-via-snarks/17473) | A special 570-bit outer curve avoids foreign-field overhead. It changes the proof backend and does not supply an optimization for the existing BN254 gnark gadget. |

## Worldcoin, Espresso Systems, Aztec and Noir

The Worldcoin review inventoried 156 public repositories and inspected the
relevant current circuit sources. Exact pinned file URLs and digests are in
`worldcoin-espresso-aztec-source-hashes.json`; the detailed dispositions are in
`worldcoin-espresso-aztec-review.json`. A fetched file is not automatically
claimed to have been reviewed: the detailed findings name the inspected paths.

| Project and source | Disposition |
|---|---|
| [World ID EdDSA circuit](https://github.com/worldcoin/world-id-protocol/blob/52262f85d3dbdaa5b0cb0fc5dadc960c1e09e6bd/circom/eddsa_poseidon2/eddsaposeidon2.circom), BabyJubJub, Dlog and inverse helpers | Uses native BabyJubJub, Poseidon2, a prime-subgroup key policy and a cofactored equation. Some Dlog checks rely on the external verifier for public-key subgroup validation. Those choices differ from the full Solana predicate. Our constrained roots and separate torsion equation retain the requested behavior. |
| [Worldcoin Remainder hashing](https://github.com/worldcoin/Remainder_CE/blob/5687fe7f3a077c75c374422ef79f22e3860de9c1/frontend/src/components/sha2_gkr.rs), nonlinear gates, SHA-256 decomposition and LogUp nodes | Has bitwise SHA helpers and GKR arithmetic/lookup layers. Their polynomial-degree and layer costs differ from R1CS; they do not supply a cheaper direct SHA-512 port. |
| [Worldcoin Semaphore Merkle helpers](https://github.com/worldcoin/semaphore-mtb/blob/3f56f6a425be50e3d4ab441f96a2e55acc52a068/prover/circuit_utils.go), proof loading, World Chain executor and Bedrock signer | Inspected native Poseidon/Merkle, proof-artifact loading, generic VM execution and host P-256 signing paths. Dependencies on signature libraries or SP1 do not establish a standalone R1CS arithmetic optimization. |
| [Espresso Jellyfish emulated Edwards](https://github.com/EspressoSystems/jellyfish/blob/b1581c26f7195962d17fc5ff3768ac55db610ca1/relation/src/gadgets/ecc/emulated/twisted_edwards.rs), generic arithmetic, nonnative gates, MSM and Schnorr | Generic multiplication proves power-of-two/native-field quotient equations. Complete Edwards formulas materialize several products that our lazy expressions already share. Native MSM uses point-window lookups; Schnorr uses Rescue and a native coordinate field. Multiple-product custom gates and narrower-target-field Rescue helpers do not transfer directly to Edwards25519 over BN254 R1CS. |
| [Aztec barretenberg P-256](https://github.com/AztecProtocol/aztec-packages/blob/bb15fcbbe969f11a892272715fe59f0976b086ca/barretenberg/cpp/src/barretenberg/stdlib/primitives/biggroup/biggroup_secp256r1.hpp), ECDSA, fixed tables and bigfield | Uses fixed windows, offsets, half-GCD and fused multiply-add certificates. These concepts are already applied here. The inspected path has restrictions for small variable-base coefficients; those cannot replace this gadget's complete scalar behavior. Its square-add helper currently delegates to multiplication rather than supplying a new square shortcut. Four binary limbs plus a native residue and custom gates have a different cost model. |
| [Aztec sparse SHA-256](https://github.com/AztecProtocol/aztec-packages/blob/bb15fcbbe969f11a892272715fe59f0976b086ca/barretenberg/cpp/src/barretenberg/stdlib/hash/sha256/sha256.cpp) | Combines sigma and choice/majority using bases 28/16. Whole 64-bit SHA-512 words would exceed the BN254 field at those bases. A split-word implementation would need a separate measured experiment; no direct savings are claimed. |
| [Noir SHA-512 encoding](https://github.com/noir-lang/sha512/blob/e92ffb473f3264529a0793770f63a09946df50cc/src/encoding.nr), permutation, formatting and table generation | Rotation-aligned slices avoid additional cut lookups. Adopted an independently constrained Go adaptation while retaining our parity-only choice/majority identities. Replacing nine-bit slices by eight-plus-one, and the seven-bit slice by six-plus-one, reduces fixed-table cost. Original byte bounds, exact typed slice ranges, 64/128-bit joins and modular carry checks remain. |

The final slicing adaptation saves 1,973 constraints for the full 32-byte
signature verifier, reaching 50,964; arithmetic remains 30,072. Standalone
SHA-512 costs 20,724 for 64 bytes and 35,588 for 128 bytes. The x10 costs are
464,039, 193,701 and 342,283 respectively. Lookup sharing means batch savings
are not ten times the single-instance savings. Exact counts, adversarial
slice-carry tests and promotion evidence are recorded in
`sha512-slicing-experiment.json`; final proving timings are in
`ed25519/BENCHMARKS.md`.

## Active P-256 worktree transfer

Inspected an immutable snapshot of `/Users/jorrit/orca/workspaces/zk-experiments/p256-opt`, based on fdce0f9 plus its uncommitted optimization campaign. The source snapshot and individual hashes are recorded in the local ignored [performance records](../../../docs/perf-loop/state.md). No files in that worktree were edited. Its P-256 layout is 8×32; Ed25519 uses 6×43.

Borrowed the idea of projecting quotient/carry checks, then derived an Ed-specific aligned quadratic CRT kernel. The generic P-256 cyclic matrix pencil did not help the binomial Ed fold. Also adopted exactly intersected lazy bounds, balanced modulus carry coefficients and degree-zero scalar extraction. Individual gains overlap; the final combined verifier is independently measured.

Explicitly rechecked inherited tuning choices:50 feasible layout/piece variants,62 baseline window/constant/joint-packing variants, then the final-kernel piece/window matrix and packing shortlist. Six 43-bit limbs, 11-bit pieces, constant X2/Y3 and joint 2 remain best among these cases. Window8 saves 28 rows and repeated identical-input timing favors it despite more coefficients and fixed-base points. Native-bound failures are retained as failures rather than weakening checks. Longer projected prefixes gave no savings and were discarded.
