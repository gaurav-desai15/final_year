#!/usr/bin/env bash
# Paced corpus eval. For each app: grounded run, then ungrounded (--grounding
# raw) run, then a cooldown -- so every completed app has the full H2
# comparison even if the whole job is cut short.
#
# Resumable: an app whose corpus/eval/<app>[-raw].json already exists is
# skipped with no cooldown. Re-run this after any interruption to continue.
#
#   ./scripts/run_corpus_eval_paced.sh [max_mutations] [cooldown_seconds]

set -u
cd "$(dirname "$0")/.."

MAXMUT="${1:-8}"
COOLDOWN="${2:-300}"
PY=".venv/bin/cpgvd"
export CPGVD_MAX_CONTEXTS="${CPGVD_MAX_CONTEXTS:-12}"
export CPGVD_LLM_CONCURRENCY="${CPGVD_LLM_CONCURRENCY:-4}"

for lf in corpus/labels/*.jsonl; do
  app="$(basename "$lf" .jsonl)"
  did_work=0
  for g in cpg raw; do
    sfx=""; [ "$g" = raw ] && sfx="-raw"
    out="corpus/eval/${app}${sfx}.json"
    if [ -f "$out" ]; then
      echo "=== skip ${app} (${g}) -- exists ==="
      continue
    fi
    echo "=== eval ${app} (${g}) $(date '+%F %T') ==="
    "$PY" corpus eval "$lf" --grounding "$g" --max-mutations "$MAXMUT" --skip-existing \
      2>&1 | grep -vE 'DEBUG|Cloning into'
    did_work=1
  done
  if [ "$did_work" = 1 ]; then
    echo "=== cooldown ${COOLDOWN}s $(date '+%F %T') ==="
    sleep "$COOLDOWN"
  fi
done

# final aggregates for both groundings
"$PY" corpus eval corpus/labels --grounding cpg --max-mutations "$MAXMUT" --skip-existing 2>&1 | grep -vE 'DEBUG'
"$PY" corpus eval corpus/labels --grounding raw --max-mutations "$MAXMUT" --skip-existing 2>&1 | grep -vE 'DEBUG'
"$PY" corpus report 2>&1 | grep -vE 'DEBUG'
echo "=== ALL DONE $(date '+%F %T') ==="
