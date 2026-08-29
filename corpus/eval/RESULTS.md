# Control-absence evaluation -- results

## Overall (pooled across apps)

| detector | apps | mutations | precision | recall | recall_raw | F1 | FP on originals |
|---|--:|--:|--:|--:|--:|--:|--:|
| cpgvd (grounded) | 1 | 2 | 0.00 | 0.00 | 0.50 | 0.00 | 3 |
| semgrep (rules only) | 5 | 96 | 0.01 | 0.53 | 0.68 | 0.03 | 85 |

## Recall by operator

| operator | cpgvd (grounded) | semgrep (rules only) |
|---|--:|--:|
| M1 | 0.00 (0/2) | 0.76 (44/58) |
| M2 | - | 0.00 (0/3) |
| M4 | - | 0.00 (0/9) |
| M5 | - | 0.27 (7/26) |

## Per app (grounded)

| app | mutations | precision | recall | recall_raw | F1 | FP orig |
|---|--:|--:|--:|--:|--:|--:|
| bradtraversy__storybooks | 2 | 0.00 | 0.00 | 0.50 | 0.00 | 3 |
