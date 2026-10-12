# Coverage

All rows reference the checked working tree in `source-hashes.json` and the per-component entries in `components/verification.md`.

| Variable/operation family | Pass 0–2 | Pass 3–4 | Pass 5–6 | Pass 7 |
|---|---|---|---|---|
| A,R,S,M bytes; digest bytes; h,S,uS | Checked: statement/compliance/dependencies | Checked: bounds/joins/canonicality entries | Checked: transcript/encoding entries | Checked: SHA, bad input, CCTV tests |
| Wa,Wr; prime components; torsion indices/constants | Checked: subgroup model | Checked: root/equality/index constraints | Checked: torsion/identity model | Checked: 320 mixed-torsion cases and forged hints |
| u,v,sign; odd/zero flags; radix4 and fixed-base digits | Checked: short-relation model | Checked: 127-bit bounds, nonzero guard, digit joins | Checked: host/circuit recoding contracts | Checked: scalar edges and hint overrides |
| j, one-hot flags, J,alphaJ; 16 table rows | Checked: bounded-offset model | Checked: selectors and exact coordinate guards | Checked: constant and lookup binding | Checked: alternate/invalid offset tests and Groth16 |
| Per-step lambda0,lambda1,mu,xD,yD,x2,x,y | Checked: cubic/group model | Checked: slope certificates and bounds | Checked: universal polynomial identities | Checked: coincident-chord and forged slope tests |
| Alias z,k,n,inv,carry and packed halves | Checked: guard interval model | Checked: integer lifts/native root inference | Checked: host alias implementation | Checked:69 boundary cases and false alias correction |
| Field result/quotient/carry/range pieces | Checked: local field contracts | Checked: coefficient/lift bounds and hints | Checked: dependency arithmetic entries | Checked: emfield and whole-module tests |
| Row indices, results, counts, challenge encodings | Checked: row/range contracts | Checked: committed variables and polynomial-degree bounds | Checked: BSB22 dependency operations | Checked: row/count forgery tests and real proofs |
| Host extended points, shared inverses, native canonical gaps and magnitude selectors | Checked: formula/interval contracts | Checked: unreduced scalar, total hint paths, signed bounds | Checked: complete Edwards formulas and selector identities | Checked: 1,076 affine-reference cases, canonical boundaries, exhaustive selectors |
| Native R1CS/bits/select/zero/commit operations | Checked: pinned dependencies | Checked: source constraints in dependencies.md | Checked: fallback and compiler contracts | Checked: whole-module tests and vet |
| Public context/privacy | Checked: statement/obligations | Checked: enclosing-circuit visibility | Checked: commitment assumptions | Checked: proof public inputs |
| Application state transitions | n.a.: no state | n.a.: no state | n.a.: no state | n.a.: no state |

Exit gate: every row filled; dependency operations cite pinned implementation locations; no open actionable leads; every named test-set input run; findings name repaired code and current rejection evidence; verifier/setup checks appear in obligations.md.
