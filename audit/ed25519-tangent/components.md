# Components

| Component | Code | Inputs and outputs | Consumer |
|---|---|---|---|
| Ladder step | ed25519/short.go: quadrupleAddChecked | accumulator, table point, three hinted slopes -> lazy affine output | next step |
| Slope guards | assertPackedDifference, assertSlopeSumNonzero | balanced mu/lambda -> nonzero output/table x difference | residual induction |
| Table and terminal | shortTable, shortVerify | checked constants and signature points -> on-curve table; final membership | induction endpoints |
| Arithmetic | internal/emfield, internal/r1c, gnark v0.16.4 R1CS API | bounded limbs and native variables -> modular equations, native equations | all constraints |
