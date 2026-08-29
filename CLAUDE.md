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

- `src/cpgvd/` — `cli.py` (thin), `pipeline.py` (CPG→Joern→context→LLM,
  reusable, Joern server injectable), `config.py`, `repo_manager.py`,
  `joern_runner.py`, `cpg_client.py`, `context_extractor.py`, `rules.py`,
  `llm_providers.py`, `llm_analyzer.py` (prompt + schema + FP guards),
  `models.py`, `report.py`, `dashboard.py`.
- `rules/sinks_sources.yaml` — per-language sink/source regexes (injection mode).
- `rules/control_absence.yaml` — per-language `triggers` / `guards` for
  `--mode absence` (missing-access-control detection).
- `mutation.py` (M1-M5 control-removal operators, `node --check` verify),
  `corpus.py` (JSONL labels, by-app split), `corpus_collect.py` (GitHub
  search + screen + clone), `evaluation.py` (score detector vs labels:
  P/R/F1 + FP-on-original). CLI: `cpgvd corpus collect|mutate|stats|eval`.
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

Control-absence mode (`--mode absence|both`, landed this session — v1):
- `rules/control_absence.yaml`: `triggers` (route regs, DB read/write, file
  send, credential handling) and `guards` (auth/authz/ownership/session/
  validation evidence). Guards deliberately match bare property access
  (`req.user`) — inverse failure mode to sinks; header in the file explains.
- `ContextExtractor.find_control_triggers` / `collect_guard_evidence`
  (handler body + real callers via regex+call-list; route-registration sites
  via "call whose code names this handler" since handlers are passed as
  args, not called) / `build_absence_context` (no dataflow).
- `FunctionContext` gains `control_triggers` / `guard_evidence` (each with
  CPG node id + line) and `to_absence_prompt_text`. Empty `guard_evidence`
  is rendered as an explicit "(none)".
- `LlmAnalyzer(mode="absence")`: 3-step prompt (classify op → infer required
  control → check guard list), own schema, own contradiction guard
  (`_asserts_control_present`).
- Verified on NodeGoat: mode runs end-to-end, contradiction guard + dedup
  fire. Known weakness (expected, tune on the mutation corpus not here): the
  local model over-reports DAO methods as missing-control despite the prompt
  caveat, and context prioritisation (by hit count) buries route handlers
  under DAO files. Refinements: rank 0-guard route handlers first; persist
  analyzed contexts to the report so `guard_evidence`+node-ids are a
  checkable artifact.

Mutation harness (`corpus mutate` / `corpus stats`, landed this session — v1):
- `mutation.py`: regex + brace-balanced text edits, NOT an AST. Operator
  vocab is deliberately kept separate from `control_absence.yaml` (mutator
  and detector must not share patterns or the eval is circular). M1 emits one
  mutation per removable route middleware, classified by name (auth vs
  admin/role). M2/M3/M4 share an `if`-statement finder + a denial-shaped-body
  filter. M5 needs a DB write within ~60 lines below the guard. Line-count
  preserving (removed lines -> blank) so labels' line ranges hold in both
  original and mutant. `mutation_applied()` context manager restores exact
  bytes; `verify_mutations()` drops mutants that fail `node --check`.
- `corpus.py`: JSONL labels, `split_by_app` (stable per-app hash -> holdout,
  order-independent, so re-collecting apps never reshuffles).
- Dry run on NodeGoat: 19 mutations, all parse-valid (16x M1, 3x M4). M2/M3/M5
  need apps with per-route inline handlers — NodeGoat centralises routing.
- `evaluation.run_eval` (landed D4): baseline run on the clean tree (its
  findings = the FP negative control), then per-mutant apply→analyse→score→
  restore, holding ONE Joern server open the whole time (`pipeline.run_pipeline`
  / `joern_session` — the D1 "one server across runs" item, done where it pays
  off). Scoring: finding within `--match-window` lines of the removed control,
  same file, not a baseline line. P/R/F1 overall + per operator + per control
  class. `cpgvd corpus eval <labels.jsonl>`.
- `analyze` now persists the analyzed `contexts` (with `guard_evidence` +
  node ids) into `report.json` — findings are checkable against what the
  model saw. Absence-mode context selection now ranks route handlers first.
- **Per-route absence context (landed):** `build_route_absence_context` makes
  ONE candidate per `app.get(...)` registration — its middleware list, the
  resolved handler body (`_resolve_handler` maps `ctrl.displayFoo` -> method),
  guards on either, anchored on the registration line so it matches an M1
  label. `pipeline.extract_contexts` splits route triggers (per-registration)
  from the rest (per-method, e.g. DAOs). Fixes the D4 smoke-test 0-recall
  cause: a centralised router is one `<module>` method with ~60 routes, and
  per-method context couldn't localise one dropped `isLoggedIn`.
- D4 smoke test (pre-fix, NodeGoat 3 M1 mutants): recall 0/3, 5 FP on the
  original. Re-running post-fix to confirm recall recovers.
- `corpus_collect.py` + `cpgvd corpus collect` (landed D5): GitHub repo
  search -> screen on package.json (express + auth lib) + permissive licence
  -> shallow clone -> mutate -> `--min-mutations` gate drops frameworks /
  boilerplates. Smoke-tested unauthenticated (2 apps): works, but naive
  search pulls frameworks (parse-server) and FE boilerplates (0 mutations)
  — **the final ~30 needs a curation pass**, and a real run needs GITHUB_TOKEN
  (unauth is ~10 search req/min).
- Still to do (D5-D6): run `corpus collect` with a token, curate to ~30 real
  apps / >=500 labelled instances, hand-verify ~10 mutations. Then the
  precision fix: teach the absence prompt/rules that public auth routes
  (/login, /signup, static) need no control — tune against corpus negatives,
  never NodeGoat/Juice Shop. Ungrounded (raw-file) baseline mode for H2.

Candidate next features (pick with the user, don't assume):
1. Widen `_NO_ATTACKER_PATH_RE` to catch "no … taint … reach… sink" phrasing.
2. Cap same-class over-reporting per file (the Broken-Auth flood).
3. `cpgvd eval` — score findings vs a labeled ground-truth file
   (Precision/Recall/F1) for the report's Measurement section.
4. More recall rules; HTML report; GitHub Action consuming the SARIF output.

## Git

- Active branch: `claude/cpg-vulnerability-detection-ds74ac`. Develop, commit,
  push there. Don't open a PR unless the user asks.
