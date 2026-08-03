# Benchmark run `2026-08-03T19-00-24Z__baseline`

> ⚠️ **Synthetic run — not a measurement.** These case results were not
> produced by a live scan (they were replayed from fixtures or archived
> reports). The numbers below demonstrate that the framework works; they
> are **not** valid results for cpgvd's detection quality and must not be
> cited as such. Run the suite on a machine with Joern and an LLM backend
> to produce real figures.

| Field | Value |
|:---|:---|
| Label | baseline |
| Created | 2026-08-03T19:00:24.127759+00:00 |
| Datasets | bundled-examples |
| Runner | replay |
| Provider / model | n/a / n/a |
| cpgvd commit | `cf1e3b9c5381` (dirty) |
| Cases | 2 ok / 2 total |
| Ground-truth entries | 5 |

Command:

```
python -m benchmark.run --runner replay --replay-source benchmark/fixtures/baseline --label baseline --dataset bundled-examples --notes Framework demonstration run from committed fixtures. Not a measurement -- replace with a live scan on a machine with Joern + an LLM backend.
```

## Headline metrics

> ℹ️ **Small sample:** only 5 ground-truth entries in this run. Precision/recall move in large jumps at this size and should be read as smoke-test signal, not as a performance measurement. Import a larger suite (OWASP Benchmark / Juliet) before drawing conclusions.

| Metric | Value |
|:---|---:|
| True positives | 3 |
| False positives | 2 |
| False negatives | 2 |
| True negatives | 0 |
| **Precision** | 60.0% |
| **Recall** | 60.0% |
| **F1** | 0.600 |

## Per-dataset

| Dataset | TP | FP | FN | Precision | Recall | F1 |
|:---|---:|---:|---:|---:|---:|---:|
| bundled-examples | 3 | 2 | 2 | 60.0% | 60.0% | 0.600 |

## Per-case

| Case | Status | TP | FP | FN | Precision | Recall | Runtime |
|:---|:---|---:|---:|---:|---:|---:|---:|
| example-flask-python | ok | 2 | 1 | 1 | 66.7% | 66.7% | 48.6s |
| example-express-javascript | ok | 1 | 1 | 1 | 50.0% | 50.0% | 39.2s |

## Per-CWE

| CWE | TP | FP | FN | Precision | Recall | F1 |
|:---|---:|---:|---:|---:|---:|---:|
| CWE-78 | 2 | 1 | 0 | 66.7% | 100.0% | 0.800 |
| CWE-89 | 1 | 0 | 1 | 100.0% | 50.0% | 0.667 |
| CWE-22 | 0 | 1 | 1 | 0.0% | 0.0% | 0.000 |

## Runtime

| Metric | Seconds |
|:---|---:|
| Total | 87.800 |
| Mean per case | 43.900 |
| Median per case | 43.900 |
| Fastest case | 39.200 |
| Slowest case | 48.600 |
| Per finding | 17.560 |

### Stage breakdown

| Stage | Total (s) | Mean (s) | Median (s) | Share |
|:---|---:|---:|---:|---:|
| joern_parse | 39.100 | 19.550 | 19.550 | 44.9% |
| llm_analysis | 32.700 | 16.350 | 16.350 | 37.5% |
| cpg_load | 7.000 | 3.500 | 3.500 | 8.0% |
| context_extraction | 4.300 | 2.150 | 2.150 | 4.9% |
| candidate_extraction | 3.200 | 1.600 | 1.600 | 3.7% |
| repo_acquisition | 0.700 | 0.350 | 0.350 | 0.8% |
| report_generation | 0.090 | 0.040 | 0.040 | 0.1% |
| deduplication | 0.030 | 0.010 | 0.010 | 0.0% |

Peak memory across cases: **412.5 MB** (mean peak 412.5 MB over 2 case(s)).
