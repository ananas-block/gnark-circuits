# Components

| Component | Location | Inputs → output/consumer |
|---|---|---|
| Transcript and SHA-512 | hasher/sha512.go; ed25519/verify.go | Original R,A,M bytes → digest → canonical h |
| Encodings and byte joins | ed25519/bytes.go; curve.go | A,R,S,digest → bounded foreign-field elements |
| Torsion decomposition | ed25519/short.go | Encoded points and hinted roots → prime components/indices |
| Short scalar relation | short.go | Canonical h,S → bounded u,v,uS and radix-four digits |
| Constant tables | short.go; montgomery.go | Selected j/digits → actual fixed multiples of B |
| Joint ladder | short.go | Prime points, table points, slopes → final prime equation |
| Foreign arithmetic/ranges | p256/emfield | Bounded integers → checked modular operations |
| Row lookup/direct R1CS | internal/lookup; internal/r1c | Committed rows/queries and field expressions → binding assertions |
| Gnark infrastructure | pinned gnark v0.16.3 | Hint outputs, boolean selectors, commitments and proofs |
| Witness/reference hosts | ed25519/testdata/oracle; host helpers | Expected acceptance/points and witness hints |

Checked component questions, evidence and revision pointers are in `components/verification.md`, `dependencies.md` and `coverage.md`.
