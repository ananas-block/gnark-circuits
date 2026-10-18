# Scope and statement

Determine whether the added coincident-chord tangent constraint in `ed25519/short.go` is implied by the preexisting Ed25519 ladder constraints. The source is commit 191d3b9 plus the uncommitted strict-check port. This is a constraint implication review, not a claim that a deployed verifying key has been audited. No deployed key is supplied.

The adversary chooses every hinted coordinate, slope, scalar reconstruction and offset. The statement to establish is: on-curve table points, both exact slope guards in each step, and the terminal curve assertion imply the correct finite `4P+T` step, including coincident points. The additional point-acceptance policy is a separate requirement and is retained.

The review checks the polynomial identities, existing native-field guards, modular-arithmetic calls used by those identities, and solver behavior with adversarial hints. Public-input layout, signature hash and privacy do not change when this additional assertion is removed; no new public values or state transitions are introduced.
