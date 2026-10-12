# Statement

Checked component: `ed25519.Verify` over BN254 R1CS. For the supplied compressed public-key bytes A, signature bytes R||S and fixed-length message M, constraints assert exactly the mathematical predicate in Agave's Ed25519 precompile (`ed25519-dalek 1.0.1`, `curve25519-dalek 3.2.0`). Both decoded points must be valid and not small-order; S must be canonical and below L; the challenge is SHA-512 of the original R,A,M bytes, reduced modulo L; `[S]B=R+[h]A` holds in the full group.

A soundness failure accepts a signature outside that predicate. A completeness failure rejects a predicate-valid input, including exceptional scalars or mixed torsion. Public/private visibility is selected by the enclosing circuit; the example and benchmark bind A and M publicly and keep the signature private. No signer private key is a witness.

Evidence: `Verify`, `verifyDigest`, `splitTorsion`, `shortVerify`; `TestDalekCCTV`, `TestShortVerificationEdgesAndMixedTorsion`, `TestRejectsBadSignaturesAndHints`; source hashes are recorded in `source-hashes.json` against the working tree based on fdce0f9.
