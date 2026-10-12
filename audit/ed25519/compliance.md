# Compliance

| Requirement | Status/evidence |
|---|---|
| Solana precompile predicate | Checked: exact dalek 1.0.1/curve 3.2.0 pin, original-byte transcript, full prime+torsion equations; 914 oracle cases. |
| In-circuit standard SHA-512 | Checked: `Sha512`; Go host differential tests and all padding boundaries. |
| Scalar and point validation | Checked: byte bounds, S/h canonicality, rooted subgroup split and identity-rejecting maps. |
| Complete exceptional/mixed-torsion behavior | Checked: bounded offsets, complete corrections, 320 independent supplied-challenge cases. |
| Lookup optimization and P-256 comparison | Checked: six 43-bit folded limbs, shared range/row arguments, lazy 127-bit checker, packed seven-bit fixed-base tables, direct R1CS; 32-byte benchmark and private arithmetic-only compilation. |
| Measured optimization goal | Arithmetic: 29,786 constraints and 96.08ms versus current P-25630,164 and 105.7ms. Full Ed25519:50,678 vs44,258 with required hashes,14.5% larger; full proof times reported separately. |
