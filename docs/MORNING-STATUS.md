# Morning status — 2026-08-30

## TL;DR

Overnight coding is done. The **paced grounded+raw eval is running** on the
expanded 13-app corpus (pid `52450`, started 00:29, ETA ~10:00–11:00). It is
resumable — if it's not finished, run `bash scripts/run_corpus_eval_paced.sh 6 300`
and it continues from where it stopped. **30 commits, unpushed.**

## What got done overnight (D7–D9)

| commit | what |
|---|---|
| `0b00a73` | **Over-escalation fix** — the detector was reporting "missing ownership" on routes that already have route-level auth. Prompt: auth-present ⇒ authentication satisfied, only escalate to ownership with a concrete cross-user path. Plus a filter. |
| `3848706` | **H3 + H5 metrics** (`src/cpgvd/metrics.py`) — compression ratio (slice/file/repo LoC) and grounded-findings ratio (cited lines were shown). Wired into `analyze` + `corpus eval`. |
| `c8291f7` | **Semgrep baseline** (comparative axis 2) — `rules/semgrep/unprotected_route.yml` + `cpgvd corpus eval-semgrep`. Result on 5 apps: precision 0.01, recall 0.53, **85 FP on originals**, M1 0.76 / M2–M4 0.00 / M5 0.27. |
| `2acc59b` | **`cpgvd corpus report`** — rolls every eval JSON into one Markdown table (grounded vs raw vs semgrep, per operator, H3/H5, per app). Writes `corpus/eval/RESULTS.md`. |
| `732073e` | **fix** — clone dirs are now PID-scoped, so concurrent `corpus eval*` runs don't rmtree each other. |
| `a27b536` | **Corpus 5→13 apps / 96→186 instances** via `corpus collect` with the token. M1 123, M2 15, **M3 12**, M4 9, M5 27. New: social-network, social-media-app, NodeAPI, expressa, instagram-mern, iCinema, Express-Starter, Express_MongoDB_Rest_API_Tutorial. |
| `449fb16` | paced eval now interleaves grounded+raw per app (so every finished app has the full H2 comparison). |

**196 tests pass.**

## First real numbers (5-app Semgrep baseline, `corpus/eval/_aggregate-semgrep.json`)

```
semgrep (rules only), 96 mutations:
  precision 0.01   recall 0.53   FP-on-originals 85
  M1 0.76 (44/58)   M2 0.00   M4 0.00   M5 0.27
```

The straw man: high M1 recall by flagging every middleware-less route, **zero**
on M2–M4 (a rule can't see a removed `if`), precision destroyed by public
routes.

## When the eval finishes

```
cpgvd corpus report          # -> corpus/eval/RESULTS.md, the H2 table
cat corpus/eval/_aggregate.json corpus/eval/_aggregate-raw.json
```

Then run the full Semgrep baseline on all 13:
```
cpgvd corpus eval-semgrep corpus/labels
```

## D10 — what's left

1. **Held-out: OWASP Juice Shop** (B6) — not built. Needs a challenge-list →
   control-class → file/route mapping. Juice Shop is TypeScript; check the
   extractor handles its `routes/*.ts`. ~1–1.5 days. This is the main
   remaining coding piece.
2. **Model swap** (comparative axis 5) — `deepseek-coder-v2:16b` is pulled.
   `CPGVD_OLLAMA_MODEL=deepseek-coder-v2:16b cpgvd corpus eval corpus/labels/keystonejs__keystone-classic.jsonl`
   Not run overnight (CPU contention). Cut first if short.
3. **Corpus toward 25 apps** — one more `corpus collect --min-stars 15
   --pushed-after 2021-01-01` pass would add ~5–8 (older tutorial apps have
   simpler inline route auth the operators catch).
4. **Results tables → Track A** (C1).

## Housekeeping

- **Revoke the GitHub token** at github.com/settings/tokens — it's in `.env`
  (git-ignored) and was only needed for the collection run.
- **Push**: 30 commits unpushed. `git push origin HEAD` from a shell that can
  unlock the SSH key (it's passphrase-protected, no agent here).
- deepseek pull log: `scratchpad/dsv2-pull.log`. Paced eval log:
  `scratchpad/paced-eval.log`.
