**Ablations over all attacked traces (hand-crafted and generic attacks) and the adaptive suite.**

| Configuration | Leaked/att. | ASR | BU | FPR | Escalated | LIS+D | Adaptive leaks |
|---|---|---|---|---|---|---|---|
| **WITNESS (full)** | 0/62 | 0.000 | 0.952 | 0.042 | 0.517 | 1.000 | 0/26 |
| WITNESS, assisted | 0/62 | 0.000 | 0.952 | 0.042 | 0.000 | 1.000 | 0/26 |
| lenient amounts | 0/62 | 0.000 | 0.952 | 0.042 | 0.517 | 1.000 | 1/26 |
| w/o S4 elimination | 0/62 | 0.000 | 0.952 | 0.042 | 0.517 | 1.000 | -- |
| w/o S5 corroboration | 0/62 | 0.000 | 0.952 | 0.042 | 0.517 | 1.000 | 0/26 |
| w/o S3 fail-closed | 0/62 | 0.000 | 0.976 | 0.021 | 0.517 | 1.000 | 0/26 |
| known payees only | 0/62 | 0.000 | 0.048 | 0.854 | 0.517 | 1.000 | -- |
| w/o uniqueness (~AuthGraph) | 62/62 | 1.000 | 0.952 | 0.042 | 0.000 | 0.087 | 13/26 |
| w/o delegation (~CaMeL/ROPE) | 0/62 | 0.000 | 0.048 | 0.854 | 0.000 | 1.000 | -- |

Removing the uniqueness check reproduces AuthGraph's laundering; refusing delegated values reproduces the strict defences' blocking. LIS+D over oracle-usable cases of the hand-crafted attacks.
