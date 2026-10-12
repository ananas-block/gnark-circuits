# Dependency operation checks

Revision: gnark v0.16.3, gnark-crypto v0.21.0, Go toolchain 1.27.1, source manifest in `source-hashes.json`. Library-source locations below are in `/Users/jorrit/go/pkg/mod/github.com/consensys/gnark@v0.16.3/`.

| Dependency operation | Checked contract and implementation evidence |
|---|---|
| R1CS booleanity | `frontend/cs/r1cs/api_assertions.go:50`: emits v(1−v)=0 and caches checked expressions. Constants 0/1 validated. |
| Native equality | `frontend/cs/r1cs/api_assertions.go:17`: emits 1·L=R; non-equal constants reject at compile. Used only where bounded integer lifting or native-field equality is intended. |
| Native select | `frontend/cs/r1cs/api.go:536`: enforces boolean selector and selects affine values. Field selection preserves interval bounds in local `p256/emfield/field.go`. |
| Zero test/hint | `frontend/cs/r1cs/api.go:642`: `m=1−a*x`, `a*m=0` determine the 0/1 result. Its inverse hint is constrained; no zero-test output is trusted. |
| Native inverse | `frontend/cs/r1cs/api.go:391`: output·input=1. Constant zero rejects. |
| Batch inverse | `frontend/cs/r1cs/api.go:333`, verification rows at 383: each output·input=1; zero denominators reject. Used for lookup query poles. |
| Unchecked division | `frontend/cs/r1cs/api.go:256`: denominator·result=numerator; zero denominator is not guarded. Used on the lookup table side; the committed-challenge pole event is included in the lookup error bound. |
| Binary decomposition/packing | `std/math/bits/conversion_binary.go:53–65`, `:71–112`: booleanity and recomposition are enforced; widths used here are below the native field width. No unconstrained options are passed. |
| Generic hints | `constraint/bn254/solver.go:476`: host outputs are assigned, not constrained. Each new hint is listed with its consumers in component coverage and overridden in negative tests where its output is semantically fixed. |
| Shared commitment | `std/multicommit/nativecommit.go:149`: collects variables before closure; `:110–130`: commits then calls each large-field callback with successive powers of the root challenge. All row/query/result/count variables are included before challenge derivation. |
| Local row/range arguments | `internal/lookup/table.go`; `p256/emfield/layout.go`: rational membership equations, committed multiplicities and spaced challenge powers. Used arguments retain over 100 bits of margin after accounting for callback powers and pole events; static degree checks reject excessive row/column configurations. |
| Local foreign arithmetic | `p256/emfield/plain.go`, `crt.go`, `canonical.go`, `field.go`: bounded product coefficients, folded congruences, bounded quotient/carry lifts, cached tensor products, canonicality. The 152 fold for 6×43 is the exact identity 2^258 modp=152; high/low lift limits are checked against native half-modulus. Binomial quadratic CRT factors use a two-product square identity; native frontend differential tests compare independent coefficient convolution/long division and exercise nonbinomial and linear+cubic fallbacks. Existing field and P-256 soundness suites pass after changes. |
| Direct native R1CS | `internal/r1c/assert.go`: generic R1C L·R=O, constant terms mapped to wire0, identical high-level fallback. Extracted from the established SHA-256 implementation; all SHA-256/BLAKE3 tests pass. |
| Hash definition/constants | `hasher/sha512.go`; Go 1.27.1 `crypto/internal/fips140/sha512`: host differential vectors and regenerated integer square/cube-root constants. Source hash and regeneration test pin the constants. |
| Elliptic/group reference | Rust dalek 1.0.1/curve 3.2.0 for acceptance; curve 4.1.3 for independent point fixtures. Oracle versions/checksums pinned in testdata/oracle/Cargo.lock. These generate tests, not proof constraints. |

Known-issue hypotheses checked: gnark's std fake-GLV signature forgery path is absent from this gadget. The local checker instead proves a bounded nonzero coefficient, subgroup splits, exact alias guards and a final curve assertion. Weak zero-denominator certificates and unbound hint results are tested directly. The existing std benchmark rows remain explicitly labeled unsound.

Privacy contract: A/M visibility is selected by the caller. Signature values and auxiliary witnesses are kept private in the benchmark. The actual Setup/Prove/Verify path includes the shared commitment; verifier/setup obligations are recorded separately.
