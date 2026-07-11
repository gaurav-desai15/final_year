# Architecture

```
                 ┌────────────────┐
  repo URL /  -->│  RepoManager   │  clone (shallow) or use local path,
  local path     │ repo_manager.py│  detect languages
                 └───────┬────────┘
                         │ repo path, commit sha, language(s)
                         v
                 ┌────────────────┐
                 │  joern-parse   │  builds a Code Property Graph (CPG)
                 │ joern_runner.py│  for the detected language
                 └───────┬────────┘
                         │ cpg.bin
                         v
                 ┌────────────────┐
                 │ joern --server │  CPGQL query server (Scala REPL over
                 │ joern_runner.py│  HTTP/WS), one process per run
                 └───────┬────────┘
                         │ CPGQLSClient (cpgqls-client)
                         v
                 ┌────────────────┐
                 │   CpgClient    │  runs Scala queries that build their
                 │ cpg_client.py  │  own JSON strings server-side, parses
                 └───────┬────────┘  the result back into Python
                         │
                         v
                 ┌────────────────────┐
                 │  ContextExtractor   │  1. fetch all methods + calls (2 queries)
                 │context_extractor.py │  2. match sink/source regex patterns in Python
                 │                      │  3. build 1-hop caller/callee graph in Python
                 │                      │  4. read real source text off disk by line range
                 │                      │  5. run `reachableByFlows` per candidate sink
                 └───────┬──────────────┘
                         │ FunctionContext[] (code + callers + callees +
                         │ imports + matched patterns + dataflow paths)
                         v
                 ┌────────────────┐
                 │  LlmAnalyzer   │  one Claude call per FunctionContext,
                 │ llm_analyzer.py│  structured-output JSON, concurrent pool
                 └───────┬────────┘
                         │ Finding[]
                         v
                 ┌────────────────┐
                 │    report.py   │  Markdown / JSON / SARIF
                 └────────────────┘
```

## Why split it this way

**CPG for structure, LLM for judgment.** Joern gives us precise, language-
agnostic facts: which function calls which, where a value could have come
from, whether a taint path from a candidate source to a candidate sink
exists at all in the graph. None of that tells you whether the finding is
*real* -- that requires understanding intent: is this parameter actually
attacker-controlled by the time it gets here? Did an intervening caller
already validate it? Is the "sink" actually dangerous in this usage, or is
it a parameterized/safe API shape that just happens to share a name with a
dangerous one? That's the part handed to Claude, with enough concrete
evidence (real code, real call sites, real dataflow paths) to make the
call defensibly rather than guessing from a bare function in isolation.

**Sink/source matching happens in Python, not Scala.** The regex rules in
`rules/sinks_sources.yaml` only need to run once over a flat list of calls
fetched in a single CPGQL query (`list_calls`), rather than as N separate
Scala queries (one per rule x language). This keeps the number of
round-trips to the Joern server constant regardless of how many rules
exist, and makes the matching logic unit-testable without a live Joern
server.

**Source code is read off disk, not from CPG `code` properties.** Different
Joern language frontends have subtly different semantics for what a
`Method.code` or `Call.code` property actually contains. Reading the real
file by the CPG-reported line range sidesteps that entirely and is easier
to reason about and test.

**Dataflow queries are best-effort.** `reachableByFlows` on a large CPG can
be slow or occasionally fail/timeout. `ContextExtractor.fetch_dataflow_paths`
catches and logs failures per-candidate rather than aborting the whole run
-- a context without a dataflow path still gets the caller/callee graph and
matched patterns, which is often enough for the LLM to reason well.

## Concurrency and cost

`LlmAnalyzer.analyze_many` runs contexts through a bounded thread pool
(`CPGVD_LLM_CONCURRENCY`, default 4) since each context is analyzed
independently. The Anthropic system prompt is marked with
`cache_control: {"type": "ephemeral"}` since it's identical across every
call in a run, so repeated analysis of the same repo (or a re-run after a
small diff) benefits from prompt caching.

## Extending sink/source coverage

`rules/sinks_sources.yaml` is intentionally coarse and easy to extend --
add a `sinks`/`sources` entry under a language key with a `pattern` (regex,
matched against both the call's short name and its full source text) and a
`category`/`cwe`. False negatives here just mean a function never gets
shortlisted for LLM analysis; false positives just mean the LLM sees an
extra context and (per its instructions) says "no vulnerability here."
Err toward recall.
