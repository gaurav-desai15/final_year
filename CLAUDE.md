# CLAUDE.md — project context for Claude Code

This file orients a Claude Code session working on **cpgvd**. Read it, then
`git log` and `README.md` for detail.

## What this project is

`cpgvd` — a CPG-based, context-aware vulnerability detector. It takes a repo
(GitHub URL or local path), builds a **Code Property Graph** with **Joern**,
extracts call-graph + data-flow **context** around candidate functions, and
asks an **LLM** whether that context is a real, exploitable vulnerability —
not just whether a dangerous pattern appears.

Pipeline: `repo -> clone -> joern-parse -> CPG -> CPGQL context extraction
-> LLM (per function, with callers/callees/dataflow) -> Markdown/JSON/SARIF report`.

Core thesis: sink/source regex rules are **recall-only**; the LLM, given real
CPG context, is the **precision** filter that decides exploitability.

## Running it (needs a real machine — not a sandbox)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
./scripts/setup_joern.sh && export JOERN_HOME="$HOME/bin/joern" && export PATH="$JOERN_HOME:$PATH"
./scripts/setup_ollama.sh            # pulls free local model qwen2.5-coder:7b
cpgvd analyze ./examples/vulnerable_app/python --language python   # fast smoke test
pytest tests/ -q                     # 63 tests, no live Joern/LLM needed (all mocked)
```

LLM backend defaults to **free local Ollama** (`qwen2.5-coder:7b`). Switch
models with `CPGVD_OLLAMA_MODEL`; paid Claude backend via `--provider anthropic`
(+ `ANTHROPIC_API_KEY`). On CPU-only machines a large/reasoning model will time
out at the default concurrency — see the "Choosing a model" table in README.

## Layout

- `src/cpgvd/` — `cli.py`, `config.py`, `repo_manager.py`, `joern_runner.py`,
  `cpg_client.py`, `context_extractor.py`, `rules.py`, `llm_providers.py`
  (Ollama/Anthropic), `llm_analyzer.py` (prompt + schema + FP guards),
  `models.py`, `report.py`, `dashboard.py`.
- `rules/sinks_sources.yaml` — per-language sink/source regexes.
- `tests/` — mocked unit tests (no live Joern/Ollama/Anthropic).
- `docs/presentation-script.md` — final-year demo runbook.

## Conventions

- Match surrounding style; keep tests mocked (never require a live Joern
  server or model in the suite). Run `pytest tests/ -q` before committing.
- Sink patterns must match real **calls**, not bare property access: require
  invocation syntax (e.g. `\.query\(`), never a `$`-anchored bare method name
  — a past bug matched `req.query` and mislabeled unrelated code as SQL
  Injection. Any new `.method`-style sink needs the same treatment + a test.

## Known state & likely next steps (as of the last remote session)

Verified on OWASP NodeGoat with qwen2.5-coder:7b:
- **True positives:** `eval()` code injection (contributions.js); NoSQL
  `$where` injection (allocations-dao.js).
- **Remaining false positives (local-model judgment limits, not pipeline bugs):**
  - hardcoded `res.redirect("/login")` flagged as Open Redirect — the model's
    own reasoning says the target isn't attacker-controlled ("no evidence of
    taint reaching this sink"). The self-contradiction guard in
    `llm_analyzer.py` (`_NO_ATTACKER_PATH_RE`) catches some phrasings but not
    this one yet — **widening it is a good next task.**
  - ~6 "Broken Authentication" findings across one DAO's methods — over-
    reporting; consider capping same-file/same-class findings.

Perf / instrumentation (landed this session):
- `RunStats` now carries per-stage wall-clock timings; `analyze` prints a
  stage-breakdown table and the Markdown report lists it. Baseline on the
  bundled python example: cpg-build ~5s, dataflow ~5s, **LLM ~88s of ~110s
  total** — the LLM stage is the thing to optimise.
- `cpg.bin` is cached under the work dir with a content-addressed name
  (`source_fingerprint` over source files, not the commit SHA — mutants share
  a SHA). Re-running the same tree skips `joern-parse`. `keep_cpg` now
  defaults true; `--no-keep-cpg` opts out.
- Removed the `or source_calls` fallback in `cli.py` that fed every source in
  the repo into `reachableByFlows` when a function had no source call.
- Still open: run one Joern server across a batch and use `importCode`
  in-server instead of `joern-parse` (one JVM not two) — belongs with the
  batch/eval runner, where it actually pays off.

Candidate next features (pick with the user, don't assume):
1. Widen `_NO_ATTACKER_PATH_RE` to catch "no … taint … reach… sink" phrasing.
2. Cap same-class over-reporting per file (the Broken-Auth flood).
3. `cpgvd eval` — score findings vs a labeled ground-truth file
   (Precision/Recall/F1) for the report's Measurement section.
4. More recall rules; HTML report; GitHub Action consuming the SARIF output.

## Git

- Active branch: `claude/cpg-vulnerability-detection-ds74ac`. Develop, commit,
  push there. Don't open a PR unless the user asks.
