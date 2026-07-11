# cpgvd — CPG-based, context-aware vulnerability detector

Takes a repository (a GitHub URL or a local path), builds a **Code
Property Graph (CPG)** of it with [Joern](https://joern.io), walks that
graph to assemble real call-graph and data-flow **context** around
candidate vulnerable code, and asks **Claude** to judge whether that
context actually constitutes an exploitable vulnerability — not just
whether a dangerous-looking function name appears somewhere.

The core idea: a pattern match on `os.system(...)` is not a finding by
itself. Whether it's dangerous depends on *who calls it and with what* —
information a single-function scanner doesn't have and a CPG does.

```
repo URL/path -> clone -> joern-parse -> CPG -> CPGQL context extraction
   -> Claude (per-function, with call graph + dataflow context) -> report
```

See [`docs/architecture.md`](docs/architecture.md) for the full pipeline
diagram and design rationale.

## Requirements

- Python 3.10+
- [Joern](https://joern.io) (`joern-parse` and `joern` on `PATH`, or set
  `JOERN_HOME`) — install with `./scripts/setup_joern.sh`, which needs a
  JDK 11+.
- An Anthropic API key (`ANTHROPIC_API_KEY`), or an `ant auth login`
  profile — see the [Claude API docs](https://platform.claude.com/docs).

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
./scripts/setup_joern.sh                 # installs Joern under ~/bin/joern
export JOERN_HOME="$HOME/bin/joern"
export PATH="$JOERN_HOME:$PATH"
cp .env.example .env                     # fill in ANTHROPIC_API_KEY if not using `ant auth login`
```

## Usage

```bash
# Analyze a GitHub repo
cpgvd analyze https://github.com/owner/repo

# Analyze a specific branch/tag/commit
cpgvd analyze https://github.com/owner/repo --ref main

# Analyze a local checkout, forcing the language and skipping dataflow
# (faster, coarser -- still uses call-graph context)
cpgvd analyze ./my-project --language python --no-dataflow

# Try it on the bundled vulnerable example app
cpgvd analyze ./examples/vulnerable_app/python --language python
```

Output goes to `cpgvd_output/` by default: `report.md` (human-readable),
`report.json` (full structured data), and `report.sarif` (for GitHub code
scanning / other SARIF-consuming tooling). Override with `--output-dir`.

Run `cpgvd analyze --help` for the full option list (model override,
concurrency via `CPGVD_LLM_CONCURRENCY`, `--max-contexts` to cap LLM spend
on huge repos, `--keep-repo` / `--keep-cpg` to inspect intermediates,
`--rules` for a custom sink/source YAML).

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
6. Each context is sent to Claude (`llm_analyzer.py`) with a system prompt
   that explicitly instructs it to use the caller/callee/dataflow evidence
   — not just the sink pattern — to decide whether this is real,
   explain *why the context mattered*, and return structured JSON
   (severity, confidence, CWE, description, suggested fix).
7. Findings are aggregated into `report.py`'s Markdown/JSON/SARIF output.

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
  llm_analyzer.py         Claude-based vulnerability judgment
  models.py               shared pydantic data models
  report.py               Markdown / JSON / SARIF rendering
rules/sinks_sources.yaml  sink & source regex rules per language
examples/vulnerable_app/  small worked examples (Flask + Express) with
                           both a safe and an unsafe call site for the
                           same sink function, to demonstrate why context
                           matters
tests/                    unit tests (no live Joern/Anthropic calls needed —
                           the CPG and LLM clients are mocked)
scripts/setup_joern.sh    installs Joern
docs/architecture.md      pipeline diagram + design rationale
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Tests mock both the Joern CPGQL client and the Anthropic client, so the
full suite runs without either Joern or a live API key.

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
