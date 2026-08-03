# Benchmarking and evaluation

The benchmark framework is cpgvd's evaluation system. It runs the detector
against repositories with known vulnerabilities, scores what came back
against that ground truth, and archives an immutable, timestamped result —
so any change to the pipeline (a prompt edit, a new sink rule, multi-hop
dataflow, a different model) can be measured rather than guessed at.

Everything below assumes you're at the repository root.

## Quick start

```bash
pip install -e ".[dev]"

# What would run?
python -m benchmark.run --dry-run

# Record a baseline (needs Joern + an LLM backend; see the main README)
python -m benchmark.run --label baseline

# Change something, then measure it
python -m benchmark.run --label prompt-v2
python -m benchmark.compare baseline prompt-v2

# Regenerate the analysis document from the latest run
python -m benchmark.analyze
```

No Joern or LLM backend on this machine? The framework still runs end to end
against checked-in fixtures:

```bash
python benchmark/scripts/make_fixtures.py
python -m benchmark.run --runner replay --replay-source benchmark/fixtures/baseline --label demo
```

Replay runs are flagged `synthetic: true` and every report they produce
carries a warning banner. They demonstrate the tooling; they are not
measurements.

## Layout

```
benchmark/
  models.py          typed structures (Dataset, GroundTruth, Metrics, RunResult, …)
  loader.py          YAML dataset loading and validation
  matcher.py         finding ↔ ground-truth matching engine
  metrics.py         aggregation: per-case, per-CWE, runtime, rankings
  storage.py         archiving and retrieving runs
  run.py             `python -m benchmark.run`
  compare.py         `python -m benchmark.compare`
  analyze.py         `python -m benchmark.analyze`
  datasets/          dataset definitions (YAML) — add new suites here
  runners/           how a case gets scanned (live cpgvd, or replay)
  evaluators/        scoring a scanned case against its ground truth
  reports/           Markdown rendering
  results/           archived runs, one timestamped directory each
  fixtures/          synthetic reports for offline testing
  scripts/           dataset importers and fixture generation
```

## How a run works

1. **Load datasets.** Every `benchmark/datasets/*.yaml` (or just the ones you
   name with `--dataset`) parses into cases with ground truth attached.
2. **Scan each case.** The `cpgvd` runner shells out to `cpgvd analyze` —
   deliberately the same command a user would type, so the numbers describe
   the shipped tool. A case that fails is recorded with `status="error"` and
   excluded from metrics; it does not abort the suite.
3. **Match.** Findings are paired against ground truth (see below).
4. **Score.** TP/FP/FN/TN per case, aggregated across the run.
5. **Archive.** A timestamped directory under `benchmark/results/` gets the
   manifest, the full result, aggregated metrics, the Markdown report, and
   the untouched cpgvd output for every case.

Runs are never modified after they're written. That immutability is what
makes the history trustworthy when the numbers go into a write-up months
later.

## Adding a dataset

Drop a YAML file into `benchmark/datasets/`. The file stem is the dataset
name. Minimal example:

```yaml
name: my-suite
description: What this suite covers and where it came from.
verified: true            # false if ground truth was auto-derived or estimated
default_language: python

# Optional: tolerances for the whole dataset (see "Matching" below)
match_policy:
  line_tolerance: 5

cases:
  - id: my-case
    repo: https://github.com/owner/repo   # or a path relative to the repo root
    ref: 3f2a9c1...                        # pin a commit — never a branch
    language: python
    label: vulnerable                      # vulnerable | safe | mixed
    scope_paths: [src/]                    # optional: ignore findings elsewhere
    analyze_args: ["--no-dataflow"]        # optional: extra cpgvd flags
    expected:
      - id: my-case-gt1                    # auto-generated if omitted
        cwe: CWE-78
        category: command-injection
        file: src/handler.py
        start_line: 42
        end_line: 48
        function: run_command
        sink: subprocess.run
        description: Why this is a vulnerability, and what context it needs.
        tags: [cross-function]
```

Every field of `expected` is optional except `id`. A signal is only scored
when the ground truth specifies it, so sparse ground truth (file + CWE only)
works fine and isn't penalised against richer entries.

`label` controls true-negative accounting:

| Label | Meaning | TN contribution |
|:---|:---|:---|
| `vulnerable` | Contains the listed vulnerabilities | none |
| `mixed` | Contains both vulnerable and safe code; only `expected` is ground truth | none |
| `safe` | Asserted to contain none of the classes we detect | 1 if the scan is clean |

Only `safe` cases produce true negatives. For `vulnerable`/`mixed` cases,
"this function is not vulnerable" isn't enumerable — there's no denominator —
so claiming TNs there would be invented precision. Precision, recall and F1
don't use TN, so this conservatism costs nothing.

### Importing standard suites

Hand-writing ground truth doesn't scale and invites error. Two importers
derive it mechanically from suites that publish their own labels:

```bash
# OWASP Benchmark — ground truth from the suite's expectedresults CSV
git clone https://github.com/OWASP-Benchmark/BenchmarkJava /tmp/owasp
python benchmark/scripts/import_owasp_benchmark.py --source /tmp/owasp --limit 200

# Juliet — ground truth from the suite's bad()/good() naming convention
python benchmark/scripts/import_juliet.py --source /tmp/juliet/testcases \
    --language c --cwe 78 --cwe 89 --limit 100
```

Both cap the case count by default. The full suites are thousands of cases;
at even a few seconds of LLM time each, an uncapped run costs days.

### Adding real CVE cases

`benchmark/datasets/cve-repos.yaml` is a documented template, empty by
design. Its header spells out the verification procedure — the short version
is: pin the commit *before* the fix, read the vulnerable function at that
commit, and record what you actually see. Ground truth taken from a CVE
summary without opening the code will corrupt every figure you report, and
the framework cannot detect that it happened.

## Matching

A finding matches a ground-truth entry when it clears the hard requirements
and scores above `min_score` on a weighted average of the applicable signals.

| Signal | Default weight | How it's scored |
|:---|---:|:---|
| `file` | 1.0 | Path-component suffix match (configurable: `exact`, `suffix`, `basename`) |
| `line` | 1.0 | 1.0 for overlapping ranges, decaying linearly to 0 at `line_tolerance` |
| `cwe` | 1.0 | 1.0 when normalised CWE ids agree (`CWE-78` ≡ `cwe 78` ≡ `CWE-78: …`) |
| `function` | 0.5 | Fuzzy identifier match (qualified names match bare ones) |
| `sink` | 0.5 | Fuzzy match against the finding's type, title, or description |

Policy knobs, settable per dataset (`match_policy:`), per case
(`match_policy:` on the case), or per run (`--line-tolerance`,
`--require-cwe`, `--min-score`):

- `line_tolerance` (default 10) — how far off a finding's lines may be.
- `require_file` (default true), `require_cwe` (default false),
  `require_line` (default false) — hard gates.
- `min_score` (default 0.5) — the threshold on the weighted average.
- `path_match` (default `suffix`), `weights`.

Three decisions worth understanding, because they shape every number:

**Never exact-line-only.** Patches shift lines, Joern frontends disagree
about where a method starts, and the LLM sometimes points at the sink line
and sometimes at the function signature. Exact matching would report those as
detection failures.

**`require_cwe` is off by default.** Models routinely report a real
vulnerability under a sibling CWE. Gating on the id would count a correct
detection as both a false positive and a false negative — a double penalty
for a labelling difference. The mismatch still lowers the score.

**One finding per ground-truth entry.** Assignment is greedy on score, so a
single broad finding can't satisfy three ground-truth entries and inflate
recall.

Tighten tolerances when ground truth is dense. `bundled-examples` sets
`line_tolerance: 3, require_line: true` because each example file places a
*safe* call site within a few lines of the vulnerable one — at the default
tolerance, a finding on the safe route matches the vulnerable route's ground
truth, converting the exact false positive the dataset exists to catch into a
spurious true positive.

## Metrics

Definitions:

- **TP** — a ground-truth vulnerability some finding matched.
- **FP** — an in-scope finding that matched no ground truth.
- **FN** — a ground-truth vulnerability nothing matched.
- **TN** — a `safe` case scanned clean (see above).
- **Precision** = TP / (TP + FP) · **Recall** = TP / (TP + FN) ·
  **F1** = harmonic mean.

Reported alongside them:

- Runtime: total, mean, median, min, max, per-finding. Median is there
  because scan durations are heavily right-skewed — one large repo drags the
  mean well above a typical case.
- Stage breakdown: seconds and share of total per pipeline stage, from the
  instrumentation in `cpgvd/timing.py`. This is what tells you whether
  performance work belongs in Joern or in the LLM step.
- Detection latency: mean case latency, and LLM seconds per analysed context
  (the figure that actually scales with repo size).
- Peak memory, where the platform reports it.
- Rankings: slowest/fastest cases, most common FP classes, most common missed
  classes, and near-miss FNs.

**Near-miss false negatives** deserve attention. A miss that scored close to
the threshold usually means the detector *did* find the vulnerability and the
matcher rejected the pairing — a CWE label difference, or line drift beyond
tolerance. Those are evaluation bugs, not detection failures. Triage them
before tuning the detector, or you'll optimise against your own harness.

## Comparing runs

```bash
python -m benchmark.compare baseline latest        # two-run regression report
python -m benchmark.compare --all                  # every run in one table
python -m benchmark.compare baseline v3 -o docs/COMPARISON.md
```

Runs are addressed by directory name, by `latest`, or by the `--label` they
were given (most recent wins — so `compare baseline latest` keeps working
after you re-measure the baseline on better hardware).

The two-run report gives metric deltas, runtime deltas, per-case F1 changes,
false-positive class changes, and — most useful when tuning — the specific
ground-truth ids that became detected or became missed. A change that keeps
F1 flat while swapping *which* vulnerabilities it finds is a real result, and
only the id-level diff shows it.

Version names come from `--label`, never a hardcoded list, so a new
experiment appears in the comparison table simply by being run.

## Result analysis document

```bash
python -m benchmark.analyze                    # latest run → docs/RESULT_ANALYSIS.md
python -m benchmark.analyze --run baseline
```

Generated entirely from the archived run, so it can be regenerated for any
past run without re-scanning. Sections: overall statistics, per-project,
per-CWE, per-category, most common false positives and negatives, near-miss
misses, top missed classes, runtime and stage breakdown, slowest/fastest
cases, memory, detection distribution, cross-run history, and recommendations
derived from what the numbers actually show.

## Reproducibility

Each archived run records the git commit and whether the tree was dirty, the
exact command, the runner and its configuration, the provider and model, the
resolved match policy, and every dataset involved. Along with pinned commits
in the datasets themselves, that's enough to re-run a measurement and get the
same answer.

Two habits make the archive worth having:

- **Pin commits in datasets.** A branch name makes an old run
  irreproducible the moment upstream pushes.
- **Don't benchmark a dirty tree** for anything you intend to cite. The
  manifest will say `git_dirty: true`, and a result you can't tie to a commit
  is a result you can't defend.

## Interpreting small samples

`bundled-examples` has 5 ground-truth entries. At that size a single finding
moves precision by 20 percentage points, and reports say so with a
small-sample banner below 20 entries. It's a smoke test — it proves the
pipeline and matcher work, and it runs in minutes without network access.

For numbers worth citing, get into the hundreds via the importers, and
report per-CWE breakdowns rather than one headline figure: a suite dominated
by command injection tells you about command-injection detection, not about
the detector.

## Extending the framework

- **New dataset** — add a YAML file. No code changes.
- **New importer** — add a script to `benchmark/scripts/` that emits the same
  YAML schema.
- **New runner** — subclass `BaseRunner` in `benchmark/runners/`, implement
  `run_case`, register it in `RUNNERS`. Useful for benchmarking a *different*
  scanner against the same ground truth, which is how you'd substantiate a
  comparison against existing tools.
- **New metric** — add a pure function of `RunResult` to `metrics.py`, surface
  it in `reports/markdown.py`.
- **New matching signal** — extend `MatchSignals` and `score_pair`, and give
  it a weight. Add tests to `tests/test_benchmark_matcher.py`: that module
  pins the decisions every published figure depends on.

Tests: `python -m pytest tests/test_benchmark_matcher.py tests/test_benchmark_framework.py -v`.
They run without Joern, without a model, and without network access.
