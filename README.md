# cpgvd — CPG-based, context-aware vulnerability detector

Takes a repository (a GitHub URL or a local path), builds a **Code
Property Graph (CPG)** of it with [Joern](https://joern.io), walks that
graph to assemble real call-graph and data-flow **context** around
candidate vulnerable code, and asks an **LLM** to judge whether that
context actually constitutes an exploitable vulnerability — not just
whether a dangerous-looking function name appears somewhere.

The core idea: a pattern match on `os.system(...)` is not a finding by
itself. Whether it's dangerous depends on *who calls it and with what* —
information a single-function scanner doesn't have and a CPG does.

```
repo URL/path -> clone -> joern-parse -> CPG -> CPGQL context extraction
   -> LLM (per-function, with call graph + dataflow context) -> report
```

**This is completely free by default.** The LLM step runs against a local
[Ollama](https://ollama.com) model — no API key, no per-token billing,
everything runs on your machine. A paid Claude API backend is available
as an opt-in (`--provider anthropic`) for higher-quality analysis.

See [`docs/architecture.md`](docs/architecture.md) for the full pipeline
diagram and design rationale.

## Requirements

- Python 3.10+
- [Joern](https://joern.io) (`joern-parse` and `joern` on `PATH`, or set
  `JOERN_HOME`) — install with `./scripts/setup_joern.sh`, which needs a
  JDK 11+.
- [Ollama](https://ollama.com) running locally — install with
  `./scripts/setup_ollama.sh`, which pulls the default model
  (`qwen2.5-coder:7b`, ~4.7GB, works fine on 8GB+ RAM; pass a smaller tag
  like `qwen2.5-coder:1.5b` for lighter hardware). **Free, no account
  needed.**
- *(Optional, paid)* An Anthropic API key (`ANTHROPIC_API_KEY`) if you want
  to use `--provider anthropic` instead — see the
  [Claude API docs](https://platform.claude.com/docs).

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
./scripts/setup_joern.sh                 # installs Joern under ~/bin/joern
export JOERN_HOME="$HOME/bin/joern"
export PATH="$JOERN_HOME:$PATH"
./scripts/setup_ollama.sh                # installs Ollama + pulls the default free model
cp .env.example .env                     # defaults are already free (Ollama); edit if you want Claude
```

To use the paid Claude backend instead, additionally run
`pip install -e ".[anthropic]"` and set `ANTHROPIC_API_KEY`.

## Usage

```bash
# Analyze a GitHub repo (free, local LLM by default)
cpgvd analyze https://github.com/owner/repo

# Analyze a specific branch/tag/commit
cpgvd analyze https://github.com/owner/repo --ref main

# Analyze a local checkout, forcing the language and skipping dataflow
# (faster, coarser -- still uses call-graph context)
cpgvd analyze ./my-project --language python --no-dataflow

# Try it on the bundled vulnerable example app
cpgvd analyze ./examples/vulnerable_app/python --language python

# Opt into the paid Claude API backend instead of the free local model
cpgvd analyze ./my-project --provider anthropic --model claude-opus-4-8
```

Output goes to `cpgvd_output/` by default: `report.md` (human-readable),
`report.json` (full structured data), and `report.sarif` (for GitHub code
scanning / other SARIF-consuming tooling). Override with `--output-dir`.

Run `cpgvd analyze --help` for the full option list (`--provider`/`--model`
to choose the LLM backend, concurrency via `CPGVD_LLM_CONCURRENCY`,
`--max-contexts` to cap how many functions get analyzed on huge repos,
`--keep-repo` / `--keep-cpg` to inspect intermediates, `--rules` for a
custom sink/source YAML).

## Choosing a model

The free/local backend runs whatever Ollama model you point it at — switch
with one env var, no reinstall of `cpgvd`:

```bash
./scripts/setup_ollama.sh gpt-oss:20b          # pull it once
export CPGVD_OLLAMA_MODEL=gpt-oss:20b           # then use it (or set it in .env)
cpgvd analyze https://github.com/owner/repo
```

The default `qwen2.5-coder:7b` is a fine free starting point, but its
judgment is the main source of false positives (e.g. flagging a
hardcoded `res.redirect("/login")` as an open redirect, or every method
of a data-access layer as "broken authentication"). Because the sink
rules are deliberately coarse and the *model* is what decides whether a
match is really exploitable, a stronger model is the highest-leverage
upgrade. Reasoning-capable models help most here — the hard calls are
"is this value attacker-controlled?" and "does a caller already enforce
auth?", which are reasoning problems, not code-completion problems.

| Model | Size / RAM | Notes |
|-------|-----------|-------|
| `qwen2.5-coder:3b`, `llama3.2:3b` | ~2GB / 8GB | Lighter than default; use only if 7b is too heavy. Expect more misses. |
| **`qwen2.5-coder:7b`** (default) | ~4.7GB / 8GB | Good baseline, decent code reasoning. |
| **`qwen2.5-coder:14b`** | ~9GB / 16GB | Safe drop-in upgrade, clearly better judgment than 7b. |
| `deepseek-coder-v2:16b` | ~9GB / 16GB | Mixture-of-experts (~2.4B active) — nearly 7b speed with more knowledge. A *code* model, so strong at understanding code but not specifically at exploitability reasoning. |
| **`gpt-oss:20b`** | ~14GB / 16GB | Open-weight (Apache-2.0) **reasoning** model — best at the exploitability call among the mid-size options. |
| `qwen3:14b` | ~9GB / 16GB | Reasoning + code with a thinking mode. |
| `qwen3:30b-a3b` | ~18GB / 24GB | Mixture-of-experts: 30B total but only ~3B active, so fast for its size. |
| `qwen2.5-coder:32b` | ~20GB / 32GB | Near-frontier open coder; strongest pure-code option. |
| `gpt-oss:120b` | ~65GB / 64GB+ | Strongest free reasoning here; needs a workstation or multi-GPU. |

Practical notes:

- **Reasoning models are slow on CPU, and concurrency makes it worse.** A
  20B reasoning model with the default 4 concurrent requests on a CPU-only
  machine will blow past the request timeout on *every* context and produce
  an empty report. If you don't have a GPU, either pick a fast model
  (`qwen2.5-coder:7b`, or the MoE `deepseek-coder-v2:16b`) or, to run a big
  model anyway, **serialize and be patient**:
  ```bash
  export CPGVD_LLM_CONCURRENCY=1      # one request at a time
  export CPGVD_OLLAMA_TIMEOUT=1800    # 30 min per context
  cpgvd analyze <repo> --max-contexts 5   # start small
  ```
  Rule of thumb: `gpt-oss:20b` / `qwen3` reasoning models want a GPU;
  on CPU-only WSL2, stick to 7b or the MoE model.
- All of these support Ollama's structured-JSON output, which the tool
  relies on. If you try a `deepseek-r1` distill and see JSON parse
  failures, that family sometimes fights the forced schema — prefer
  `gpt-oss` or `qwen3` for reliable structured output.
- Still weaker than `--provider anthropic` (Claude) at nuanced context
  judgment. If you want a precision ceiling to compare against, run the
  same repo through the paid backend once — same CPG, same rules, so any
  difference in the findings is purely model quality.

## Interactive dashboard

For an interactive view of a report instead of reading `report.md`:

```bash
pip install -e ".[dashboard]"
cpgvd dashboard --report cpgvd_output/report.json
```

Opens a Streamlit app in your browser: summary metrics, a severity
breakdown chart, a filterable/sortable findings table (by severity,
confidence, or a text search), a CSV export, and an expandable detail
view per finding (description, why the context mattered, data flow,
suggested fix). It only reads the JSON report already on disk -- no
Joern or LLM calls happen here, so it's safe to re-run against any past
report, or point it at one via the sidebar / a direct file upload.

## How a finding gets made

1. **Clone & detect language** (`repo_manager.py`).
2. **`joern-parse`** builds `cpg.bin` for the repo.
3. A **`joern --server`** CPGQL query server loads it, and `context_extractor.py`
   fetches every method and every call in the codebase in two queries.
4. Calls are matched in Python against `rules/sinks_sources.yaml`
   (regexes per language: command injection, SQLi, path traversal, SSRF,
   insecure deserialization, XSS, memory-safety sinks, etc.) to shortlist
   candidate functions.
5. For each candidate function, a **`FunctionContext`** is assembled: its
   own source (read directly off disk by CPG-reported line range), its
   1-hop callers and callees, the file's imports, and any concrete
   `reachableByFlows` taint paths Joern's dataflow engine found from a
   plausible source to the matched sink.
6. Each context is sent to the LLM (`llm_analyzer.py`, via a free local
   Ollama model by default or the paid Claude API with `--provider
   anthropic`) with a system prompt that explicitly instructs it to use
   the caller/callee/dataflow evidence — not just the sink pattern — to
   decide whether this is real, explain *why the context mattered*, and
   return structured JSON (severity, confidence, CWE, description,
   suggested fix).
7. Two false-positive guards run over the model's raw findings: any
   finding whose own reasoning asserts that no attacker-controlled path
   exists is dropped (weaker local models sometimes emit these
   self-contradictions), and near-identical findings for the same
   file/CWE/line-range — typically the same sink analyzed via both a
   caller's and its own context — are deduplicated, keeping the
   highest-severity one.
8. Findings are aggregated into `report.py`'s Markdown/JSON/SARIF output.

## Project layout

```
src/cpgvd/
  cli.py               entrypoint (`cpgvd analyze ...`)
  config.py             environment-driven configuration
  repo_manager.py        clone / detect languages
  joern_runner.py        joern-parse + joern --server process management
  cpg_client.py           CPGQL query execution + JSON result parsing
  context_extractor.py     CPG -> FunctionContext (sinks, sources, call graph, dataflow)
  rules.py                 loads rules/sinks_sources.yaml
  llm_providers.py        Ollama (free) / Claude (paid) backends behind one interface
  llm_analyzer.py         provider-agnostic vulnerability judgment + prompt/schema
  models.py               shared pydantic data models
  report.py               Markdown / JSON / SARIF rendering
  dashboard.py            Streamlit dashboard (`cpgvd dashboard`), reads report.json
rules/sinks_sources.yaml  sink & source regex rules per language
examples/vulnerable_app/  small worked examples (Flask + Express) with
                           both a safe and an unsafe call site for the
                           same sink function, to demonstrate why context
                           matters
tests/                    unit tests (no live Joern/Ollama/Anthropic calls
                           needed — the CPG and LLM clients are mocked)
scripts/setup_joern.sh    installs Joern
scripts/setup_ollama.sh   installs the free local LLM backend
docs/architecture.md      pipeline diagram + design rationale
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Tests mock the Joern CPGQL client and both LLM providers, so the full
suite runs without live Joern, a running Ollama server, or an Anthropic
API key.

## Notes & limitations

- Sink/source rules are intentionally coarse regexes meant for *recall*,
  not precision — the LLM step is what filters false positives, using the
  actual call graph and dataflow evidence.
- Dataflow queries (`reachableByFlows`) are best-effort: they're skipped
  per-candidate on failure/timeout rather than aborting the run, and can
  be disabled entirely with `--no-dataflow` for a faster, cheaper pass.
- Exact CPGQL query behavior (e.g. `Method.code`/`Call.code` semantics)
  varies slightly across Joern's language frontends; this project reads
  source text directly off disk by line range instead of trusting those
  properties, to stay robust across languages and Joern versions.
- The free local model is meaningfully weaker than Claude at nuanced
  context judgment (e.g. "is this caller's validation actually sufficient
  to neutralize this taint path?"). Expect more false positives/negatives
  than `--provider anthropic`. For coursework/demo purposes it's a solid
  free option; for anything higher-stakes, the paid backend is worth it.
- A single local Ollama instance handling several concurrent requests
  (`CPGVD_LLM_CONCURRENCY`, default 4) can be slow on CPU-only machines —
  lower it (e.g. `CPGVD_LLM_CONCURRENCY=1`) if requests start timing out.
