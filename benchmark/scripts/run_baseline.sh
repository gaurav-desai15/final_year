#!/usr/bin/env bash
#
# Record a baseline benchmark run.
#
# Run this once on the machine you intend to do all your measurements on,
# before making any detector changes. Everything you measure afterwards gets
# compared against it:
#
#     benchmark/scripts/run_baseline.sh
#     # ... change a prompt / rule / model ...
#     python -m benchmark.run --label prompt-v2
#     python -m benchmark.compare baseline prompt-v2
#
# Runtime figures are only comparable across runs on the SAME hardware with
# the SAME model, so re-record the baseline (same `--label baseline`; label
# resolution picks the most recent) if either changes.
#
# Usage:
#   benchmark/scripts/run_baseline.sh [extra args passed to benchmark.run]
#
# Examples:
#   benchmark/scripts/run_baseline.sh --dataset bundled-examples
#   benchmark/scripts/run_baseline.sh --provider anthropic --model claude-opus-4-8

set -euo pipefail

cd "$(dirname "$0")/../.."

if ! command -v joern-parse >/dev/null 2>&1 && [ -z "${JOERN_HOME:-}" ]; then
    echo "error: Joern not found on PATH and JOERN_HOME is unset." >&2
    echo "       Install it with ./scripts/setup_joern.sh, then:" >&2
    echo "         export JOERN_HOME=\"\$HOME/bin/joern\"" >&2
    echo "         export PATH=\"\$JOERN_HOME:\$PATH\"" >&2
    exit 1
fi

# A dirty tree makes a result impossible to tie back to a commit. The manifest
# records it either way, but warn loudly -- a baseline you can't reproduce is
# not a baseline.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo "warning: working tree is dirty; this run will be recorded as git_dirty=true." >&2
    echo "         Commit first if you intend to cite these numbers." >&2
fi

echo "Recording baseline. This performs live scans -- expect it to take a while."
echo

python -m benchmark.run \
    --label baseline \
    --notes "Baseline recorded by benchmark/scripts/run_baseline.sh on $(uname -s) $(uname -m)" \
    "$@"

echo
echo "Baseline recorded. Next steps:"
echo "  python -m benchmark.analyze                  # -> docs/RESULT_ANALYSIS.md"
echo "  python -m benchmark.compare baseline latest  # after your next run"
