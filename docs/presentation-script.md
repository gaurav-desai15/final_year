# cpgvd — Presentation Script

A speaking script + live-demo runbook for presenting the project. Timings
assume a ~12-minute slot; trim the demo if you have less. Everything here
uses the **free local model (qwen2.5-coder:7b)** — no API key, runs on the
laptop.

> **Golden rule of live demos:** have a fallback. A NodeGoat run takes
> several minutes on CPU, so **pre-run it before you present** and keep the
> `report.md` open in a tab. Do the *fast* bundled-example run live, and
> *show* the pre-generated NodeGoat report. Never run an 8-minute scan in
> front of examiners.

---

## 0. One-line pitch (say this first, ~15s)

> "Most vulnerability scanners flag a dangerous-looking function and leave
> you to figure out if it's actually exploitable. My project uses a Code
> Property Graph to gather the surrounding context — who calls this
> function, with what data — and then an LLM to make the judgment call a
> pattern-matcher can't. And it runs completely free and locally."

---

## 1. The problem (~1.5 min) — Slide: "A pattern match is not a vulnerability"

Talking points:

- Traditional static analysis (grep-style / regex rules) matches on
  *shape*: it sees `os.popen(command)` and shouts "command injection!"
- But the exact same line is **safe or dangerous depending on where
  `command` comes from**:
  - If it's a value from a fixed allowlist → safe.
  - If it's `request.args.get("cmd")` → remote code execution.
- A scanner that only looks at one function *cannot* tell these apart. It
  either floods you with false positives or misses real bugs.
- **The missing ingredient is context**: the call graph (who calls whom)
  and the data flow (where does this value originate).

Transition:

> "So the project has two halves: something that gathers that context
> precisely, and something that reasons about it."

---

## 2. How it works (~2.5 min) — Slide: the pipeline diagram

Draw / show this flow:

```
repo URL ─▶ clone ─▶ joern-parse ─▶ CPG ─▶ CPGQL context extraction
   ─▶ LLM (per function, with call-graph + dataflow context) ─▶ report
```

Explain each stage in one sentence:

1. **Clone & detect language** — takes a GitHub URL or local path, works
   out what language the repo is (JS, Python, Java, …).
2. **Joern builds a Code Property Graph** — a single graph that combines
   the AST, control-flow, and data-flow of the whole codebase. This is the
   "understands the code structurally" part.
3. **Context extraction (CPGQL queries)** — I query the graph for every
   method and every call, then match calls against coarse **sink/source
   rules** (regexes for SQLi, command injection, XSS, SSRF, NoSQL, etc.) to
   *shortlist* candidate functions. Crucially I also pull each candidate's
   **1-hop callers and callees** and any **Joern data-flow paths**.
4. **LLM judgment** — each candidate, *with its context*, goes to the LLM.
   The system prompt tells it explicitly: a sink match is not a finding;
   use the callers to decide if attacker input can actually reach it. It
   returns structured JSON — severity, confidence, CWE, reasoning, fix.
5. **Report** — findings are written as Markdown, JSON, and SARIF.

Key design point to emphasize (examiners love this):

> "The regex rules are deliberately **coarse — tuned for recall, not
> precision**. Their only job is 'this might be worth a closer look.' The
> LLM, seeing the real call graph, is what decides whether it's actually
> exploitable. That division of labour is the whole thesis."

---

## 3. LIVE DEMO — the bundled example (~3 min)

This is the centerpiece. It's fast, deterministic in shape, and proves the
thesis in 30 seconds of output. **Run this live.**

### Setup (have this already done before you present)

```bash
cd ~/final_year
source .venv/bin/activate
# Ollama already running, qwen2.5-coder:7b already pulled
export JOERN_HOME="$HOME/bin/joern"
export PATH="$JOERN_HOME:$PATH"
```

### Show the example source first (~45s)

Open `examples/vulnerable_app/python/app.py` and point at **one function
called from two places**:

- `run_diagnostic(command)` → calls `os.popen(command)`. On its own, you
  *cannot* say if it's safe.
- `status()` calls it with a value from a **fixed allowlist** → SAFE.
- `admin_run()` calls it with `request.args.get("cmd")` → **VULNERABLE
  (RCE)**.

Say:

> "Same sink function. One caller is safe, one is a remote code execution
> hole. A single-function scanner sees only `run_diagnostic` and has to
> guess. Let's see what mine does."

### Run it live (~1.5 min)

```bash
cpgvd analyze ./examples/vulnerable_app/python --language python
```

While it runs, narrate what's happening: "It's building the CPG with
Joern now… loading it into the query server… shortlisting candidate
functions by sink pattern… and now each candidate plus its callers is
going to the local qwen model."

### Show the result (~45s)

```bash
cat cpgvd_output/report.md
```

Point at two things in the output:

1. It flags the **command injection reachable via `admin_run`** — and the
   `context_reasoning` field explicitly says *why*: attacker input from
   `request.args` reaches `os.popen` through the caller.
2. It does **not** raise the same alarm for the allowlisted `status`
   path — because the context shows the value is constrained.

Say:

> "That distinction — same sink, different verdict based on the caller —
> is exactly what a context-free scanner can't do. The CPG gave it the
> caller; the LLM made the call."

---

## 4. Real-world evidence — OWASP NodeGoat (~2 min) — show pre-run report

Switch to the **pre-generated** NodeGoat report (don't run it live).

Frame it honestly — examiners respect honest evaluation far more than
"it's perfect":

> "I tested it on OWASP NodeGoat, a deliberately vulnerable Node.js app
> that's an industry-standard teaching target. Here's what the free local
> model found."

**True positives (lead with these):**

- **Code Injection (`eval()`) in contributions.js** — real. User-supplied
  `req.body` fields are passed straight to `eval()`. Classic RCE.
- **NoSQL Injection in allocations-dao.js** — this is NodeGoat's flagship
  bug: an unsanitized `threshold` value is concatenated into a MongoDB
  `$where` clause. My tool caught it, and the reasoning correctly traces
  `threshold` from the caller into the query string.

**Then the honest part — false positives, and what I did about them:**

- Early on, a **regex-anchoring bug** in my own rules made the SQL sink
  pattern match ordinary `req.query` property access, mislabeling three
  unrelated issues as "SQL Injection." I found it by comparing the tool's
  output to the real source, **fixed the rules, and added regression
  tests.**
- The weak 7B local model sometimes **over-reports** — e.g. flagging a
  hardcoded `res.redirect("/login")` as an open redirect even though its
  *own* reasoning says the target isn't attacker-controlled. I added a
  **self-contradiction guard** that drops findings whose own data-flow
  summary argues against exploitability, plus **deduplication** for
  repeated findings.

Key message:

> "The pipeline is sound — same CPG, same rules. The remaining false
> positives are the *model's* judgment limits, not the architecture's.
> And I can prove that: swapping in a stronger model, or the paid Claude
> backend, removes them without changing a line of the pipeline."

---

## 5. What makes it notable (~1 min) — Slide: contributions

- **Context-aware, not pattern-only** — combines CPG structure with LLM
  reasoning; each finding explains *why the context mattered*.
- **Free and local by default** — runs on Ollama with an open model, no
  API key, no per-token cost; a paid Claude backend is an opt-in for
  higher precision. Same code path either way.
- **Multi-language** — 9 languages via Joern's frontends and per-language
  rule sets.
- **Real, honest evaluation** — tested on real vulnerable apps, with the
  false positives diagnosed and driven back into the rules and prompt.
- **Engineered properly** — 63 unit tests, mocked so they run without
  Joern or a live model; Markdown/JSON/SARIF output; an optional
  Streamlit dashboard.

---

## 6. Limitations & future work (~1 min) — say this before they ask

- The free 7B model is the accuracy bottleneck; a reasoning-capable or
  larger model (or the Claude backend) measurably cuts false positives.
- Recall is bounded by the sink/source rules — a vulnerability class with
  no rule never gets shortlisted.
- Dataflow queries are best-effort and can be slow on very large graphs.
- **Future work:** finding-level dedup across call chains, richer
  inter-procedural dataflow, auto-tuning rules from confirmed findings,
  and a CI/GitHub-Action mode using the SARIF output.

Close:

> "In short: a CPG gives precise structural context, an LLM turns that
> context into a judgment, and the result is a scanner that explains its
> reasoning — running for free on a laptop. Thank you — happy to take
> questions."

---

## Q&A — likely examiner questions & crisp answers

**"Isn't this just ChatGPT reading code?"**
No — a raw LLM sees only the text you paste. The CPG lets me pull the
*exact* callers, callees, and data-flow paths from across the whole
repo and feed only that relevant context. It's retrieval over a
program graph, not a chat window.

**"Why Joern / why a CPG?"**
A CPG unifies AST + control-flow + data-flow in one queryable graph, and
Joern supports many languages with a real inter-procedural dataflow
engine (`reachableByFlows`). It's the standard tool for this.

**"How do you handle LLM hallucination / false positives?"**
Three ways: a system prompt that demands evidence-based reasoning and an
empty result when nothing's exploitable; a structural guard that drops
findings contradicting their own reasoning; and deduplication. And the
regex layer is recall-only, so the LLM is a *filter*, not the sole
decider.

**"Why is the local model weaker?"**
7B parameters. It's strong at reading code but weaker at nuanced
judgment like "does this caller's validation fully neutralize the
taint?" I designed the provider layer so a stronger model is a one-line
env-var change — the pipeline is model-agnostic.

**"How do you know your findings are correct?"**
I validated against known-vulnerable apps (NodeGoat, a bundled example)
by reading the real source and comparing. That's how I found — and fixed
— a bug in my own rules.

**"Does it scale to large repos?"**
Context extraction is a constant number of CPG queries regardless of repo
size; the LLM cost is bounded by `--max-contexts`. Dataflow is the
expensive part and can be disabled with `--no-dataflow`.

---

## Demo cheat-sheet (keep this visible during the talk)

```bash
# one-time, before the talk:
cd ~/final_year && source .venv/bin/activate
export JOERN_HOME="$HOME/bin/joern"; export PATH="$JOERN_HOME:$PATH"
ollama list                      # confirm qwen2.5-coder:7b is present

# pre-run NodeGoat and keep the report open in a tab:
cpgvd analyze https://github.com/OWASP/NodeGoat --max-contexts 15
cp -r cpgvd_output cpgvd_output_nodegoat   # save it

# LIVE during the talk (fast, ~1-2 min):
cpgvd analyze ./examples/vulnerable_app/python --language python
cat cpgvd_output/report.md

# optional wow-factor: the dashboard
cpgvd dashboard --report cpgvd_output_nodegoat/report.json
```

If the live run fails for any reason: stay calm, say "I have a recorded
run here," and switch to the saved `report.md`. Examiners care that you
understand it, not that the laptop cooperated.
