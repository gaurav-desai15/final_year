# Benchmark comparison: `2026-08-03T19-00-29Z__prompt-v2` vs `2026-08-03T19-00-24Z__baseline`

- **Baseline:** `2026-08-03T19-00-24Z__baseline` (baseline, n/a)
- **Candidate:** `2026-08-03T19-00-29Z__prompt-v2` (prompt-v2, n/a)

> ⚠️ One or both runs are **synthetic** (replayed, not measured). This comparison demonstrates the tooling only.

## Metric deltas

| Metric | Baseline | Candidate | Delta |
|:---|---:|---:|---:|
| Precision | 60.0% | 100.0% | 🟢 +40.0pp |
| Recall | 60.0% | 100.0% | 🟢 +40.0pp |
| F1 | 0.600 | 1.000 | 🟢 +0.4 |
| True positives | 3 | 5 | 🟢 +2 |
| False positives | 2 | 0 | 🟢 -2 |
| False negatives | 2 | 0 | 🟢 -2 |

## Runtime deltas

| Metric | Baseline (s) | Candidate (s) | Delta |
|:---|---:|---:|---:|
| Total | 87.800 | 93.800 | 🔴 +6.0 |
| Mean per case | 43.900 | 46.900 | 🔴 +3.0 |
| Median per case | 43.900 | 46.900 | 🔴 +3.0 |

## Newly detected vulnerabilities

| Ground truth id |
|:---|
| express-path-traversal-files |
| flask-sqli-query-builder |

## Newly missed vulnerabilities (regressions)

_None._

## False-positive class changes

| FP class | Baseline | Candidate | Delta |
|:---|---:|---:|---:|
| CWE-22 / Path Traversal | 1 | 0 | -1 |
| CWE-78 / OS Command Injection | 1 | 0 | -1 |

## Per-case F1

| Case | Baseline F1 | Candidate F1 | Delta |
|:---|---:|---:|---:|
| example-express-javascript | 0.500 | 1.000 | 🟢 +50.0pp |
| example-flask-python | 0.667 | 1.000 | 🟢 +33.3pp |

## Verdict

**Improvement:** F1 0.600 → 1.000 (+0.400), precision 60.0% → 100.0%, recall 60.0% → 100.0%.
