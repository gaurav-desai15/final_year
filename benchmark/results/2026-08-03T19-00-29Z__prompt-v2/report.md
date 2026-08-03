# Benchmark run `2026-08-03T19-00-29Z__prompt-v2`

> ⚠️ **Synthetic run — not a measurement.** These case results were not
> produced by a live scan (they were replayed from fixtures or archived
> reports). The numbers below demonstrate that the framework works; they
> are **not** valid results for cpgvd's detection quality and must not be
> cited as such. Run the suite on a machine with Joern and an LLM backend
> to produce real figures.

| Field | Value |
|:---|:---|
| Label | prompt-v2 |
| Created | 2026-08-03T19:00:29.040352+00:00 |
| Datasets | bundled-examples |
| Runner | replay |
| Provider / model | n/a / n/a |
| cpgvd commit | `cf1e3b9c5381` (dirty) |
| Cases | 2 ok / 2 total |
| Ground-truth entries | 5 |

Command:

```
python -m benchmark.run --runner replay --replay-source benchmark/fixtures/improved --label prompt-v2 --dataset bundled-examples --notes Framework demonstration: hypothetical precision fix, for exercising the comparison tooling. Not a measurement.
```

## Headline metrics

> ℹ️ **Small sample:** only 5 ground-truth entries in this run. Precision/recall move in large jumps at this size and should be read as smoke-test signal, not as a performance measurement. Import a larger suite (OWASP Benchmark / Juliet) before drawing conclusions.

| Metric | Value |
|:---|---:|
| True positives | 5 |
| False positives | 0 |
| False negatives | 0 |
| True negatives | 0 |
| **Precision** | 100.0% |
| **Recall** | 100.0% |
| **F1** | 1.000 |

## Per-dataset

| Dataset | TP | FP | FN | Precision | Recall | F1 |
|:---|---:|---:|---:|---:|---:|---:|
| bundled-examples | 5 | 0 | 0 | 100.0% | 100.0% | 1.000 |

## Per-case

| Case | Status | TP | FP | FN | Precision | Recall | Runtime |
|:---|:---|---:|---:|---:|---:|---:|---:|
| example-flask-python | ok | 3 | 0 | 0 | 100.0% | 100.0% | 52.1s |
| example-express-javascript | ok | 2 | 0 | 0 | 100.0% | 100.0% | 41.7s |

## Per-CWE

| CWE | TP | FP | FN | Precision | Recall | F1 |
|:---|---:|---:|---:|---:|---:|---:|
| CWE-78 | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 |
| CWE-89 | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 |
| CWE-22 | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 |

## Runtime

| Metric | Seconds |
|:---|---:|
| Total | 93.800 |
| Mean per case | 46.900 |
| Median per case | 46.900 |
| Fastest case | 41.700 |
| Slowest case | 52.100 |
| Per finding | 18.760 |

### Stage breakdown

| Stage | Total (s) | Mean (s) | Median (s) | Share |
|:---|---:|---:|---:|---:|
| llm_analysis | 39.800 | 19.900 | 19.900 | 42.5% |
| joern_parse | 38.500 | 19.250 | 19.250 | 41.1% |
| cpg_load | 7.000 | 3.500 | 3.500 | 7.5% |
| context_extraction | 4.500 | 2.250 | 2.250 | 4.8% |
| candidate_extraction | 3.100 | 1.550 | 1.550 | 3.3% |
| repo_acquisition | 0.700 | 0.350 | 0.350 | 0.7% |
| report_generation | 0.090 | 0.040 | 0.040 | 0.1% |
| deduplication | 0.040 | 0.020 | 0.020 | 0.0% |

Peak memory across cases: **412.5 MB** (mean peak 412.5 MB over 2 case(s)).
