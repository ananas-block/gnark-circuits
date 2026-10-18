# Obligations

- Verify the full Groth16 proof with its BSB22 commitment metadata and the matching circuit/verifying key. Range membership (`internal/emfield/layout.go:253`) and row membership (`internal/lookup/table.go:73`) commit witness values before their challenge; without commitment binding, the native rational identities are not sound lookup arguments.
- A changed constraint system requires matching setup artifacts. This review has no deployed verifying-key input and makes no assertion about one. The experiment generates a new setup and verifies a full-signature proof.
- Any caller reusing the lazy step without its explicit tangent check must preserve on-curve table points, both exact slope guards at every step, and the final on-curve anchor. Removing one of these invalidates the proof in models.md.
