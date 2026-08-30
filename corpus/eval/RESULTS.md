# Control-absence evaluation -- results

## Overall (pooled across apps)

| detector | apps | mutations | precision | recall | recall_raw | F1 | FP on originals |
|---|--:|--:|--:|--:|--:|--:|--:|
| cpgvd (grounded) | 13 | 39 | 0.04 | 0.18 | 0.39 | 0.06 | 47 |
| cpgvd (ungrounded) | 13 | 39 | 0.07 | 0.26 | 0.26 | 0.11 | 34 |
| semgrep (rules only) | 5 | 96 | 0.01 | 0.53 | 0.68 | 0.03 | 85 |

## Recall by operator

| operator | cpgvd (grounded) | cpgvd (ungrounded) | semgrep (rules only) |
|---|--:|--:|--:|
| M1 | 0.38 (6/16) | 0.44 (7/16) | 0.76 (44/58) |
| M2 | 0.09 (1/11) | 0.00 (0/11) | 0.00 (0/3) |
| M3 | 0.00 (0/6) | 0.00 (0/6) | - |
| M4 | - | - | 0.00 (0/9) |
| M5 | 0.00 (0/6) | 0.50 (3/6) | 0.27 (7/26) |

## H3 / H5 (grounded runs)

- **Compression (H3):** the CPG slice is on average **42.8%** of the file it came from.
- **Grounded findings (H5):** **92%** of findings cite line numbers that were in the context shown.

## Held-out apps (B6 -- externally-authored ground truth, never tuned against)

| app | grounding | labels | detected | recall | class-match | unmatched findings |
|---|---|--:|--:|--:|--:|--:|
| juice-shop | cpg | 8 | 2 | 0.25 | 0.50 | 3 |

Recall by control class (grounded held-out run):

| control class | juice-shop (cpg) |
|---|--:|
| authorization | 0.33 (1/3) |
| ownership | 0.25 (1/4) |
| validation | 0.00 (0/1) |

## Per app (grounded)

| app | mutations | precision | recall | recall_raw | F1 | FP orig |
|---|--:|--:|--:|--:|--:|--:|
| Shyam-Chen__Express-Starter | 3 | 0.09 | 0.67 | 0.67 | 0.16 | 5 |
| bradtraversy__storybooks | 3 | 0.08 | 0.33 | 0.67 | 0.12 | 3 |
| dmalvia__Express_MongoDB_Rest_API_Tutorial | 3 | 0.00 | 0.00 | 0.33 | 0.00 | 3 |
| ealeksandrov__NodeAPI | 3 | 0.04 | 0.33 | 0.33 | 0.07 | 6 |
| hagopj13__node-express-boilerplate | 3 | 0.00 | 0.00 | 1.00 | 0.00 | 4 |
| ihtasham42__social-media-app | 3 | 0.00 | 0.00 | 0.00 | 0.00 | 1 |
| jigar-sable__instagram-mern | 3 | 0.04 | 0.33 | 0.33 | 0.08 | 5 |
| keystonejs__keystone-classic | 3 | 0.00 | 0.00 | 0.00 | 0.00 | 5 |
| madhums__node-express-mongoose-demo | 3 | 0.00 | 0.00 | 0.00 | 0.00 | 2 |
| misa-j__social-network | 3 | 0.00 | 0.00 | 0.00 | 0.00 | 5 |
| orifmilod__iCinema | 3 | 0.33 | 0.67 | 0.67 | 0.44 | 1 |
| sahat__hackathon-starter | 3 | 0.00 | 0.00 | 1.00 | 0.00 | 1 |
| thomas4019__expressa | 3 | 0.00 | 0.00 | 0.00 | 0.00 | 6 |
