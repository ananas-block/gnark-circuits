# Verifier and setup obligations

Checked obligation: verify with the BSB22-aware Groth16 verifier and the exact generated verifying key. Lookup/range arguments rely on a challenge bound to their committed table data, query values, outputs and multiplicities; accepting a proof with those checks omitted invalidates the range and row-membership constraints.

Checked obligation: public inputs supplied to the enclosing application must identify the key and message that application intends to authorize. `Verify` supplies the mathematical signature predicate; the example and benchmark expose both A and M.

Checked obligation: use the BN254 scalar field and a sound Groth16 setup. The host constants, limb bounds, alias bounds and lookup security checks are pinned by the source manifest. Benchmarks run actual Setup/Prove/Verify, including commitment proofs.
