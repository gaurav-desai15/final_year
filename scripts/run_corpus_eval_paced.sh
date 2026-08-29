#!/usr/bin/env bash
# Paced corpus eval: grounded then raw, over every label file, with a 20-minute
# cooldown after each app so the CPU (and the local model) get a break.
#
# Resumable: an app whose corpus/eval/<app>[-raw].json already exists is
# skipped with no cooldown, so re-running this after an interruption continues
# from where it stopped.
#
#   ./scripts/run_corpus_eval_paced.sh [max_mutations] [cooldown_seconds]

set -u
cd "$(dirname "$0")/.."

MAXMUT="${1:-12}"
COOLDOWN="${2:-1200}"
PY=".venv/bin/cpgvd"
export CPGVD_MAX_CONTEXTS="${CPGVD_MAX_CONTEXTS:-12}"
export CPGVD_LLM_CONCURRENCY="${CPGVD_LLM_CONCURRENCY:-4}"

for g in cpg raw; do
  sfx=""; [ "$g" = raw ] && sfx="-raw"
  for lf in corpus/labels/*.jsonl; do
    app="$(basename "$lf" .jsonl)"
    out="corpus/eval/${app}${sfx}.json"
    if [ -f "$out" ]; then
      echo "=== skip ${app} (${g}) -- ${out} exists ==="
      continue
    fi
    echo "=== eval ${app} (${g}) $(date '+%F %T') ==="
    "$PY" corpus eval "$lf" --grounding "$g" --max-mutations "$MAXMUT" --skip-existing \
      2>&1 | grep -vE 'DEBUG|Cloning into'
    echo "=== cooldown ${COOLDOWN}s $(date '+%F %T') ==="
    sleep "$COOLDOWN"
  done
  # rebuild the aggregate over all per-app JSONs for this grounding
  "$PY" corpus eval corpus/labels --grounding "$g" --max-mutations "$MAXMUT" --skip-existing \
    2>&1 | grep -vE 'DEBUG|Cloning into'
done

echo "=== ALL DONE $(date '+%F %T') ==="
