"""cpgvd benchmark framework.

The project's evaluation system: runs cpgvd against datasets with known
ground truth, scores the findings, and archives immutable, timestamped
results so any change to the detector can be measured against a baseline.

Entrypoints:

    python -m benchmark.run       scan a suite and archive the result
    python -m benchmark.compare   diff two archived runs
    python -m benchmark.analyze   generate docs/RESULT_ANALYSIS.md

See `docs/benchmarking.md` for the dataset schema and metric definitions.
"""

from __future__ import annotations

import sys
from pathlib import Path

# The benchmark imports cpgvd models. Support running straight from a source
# checkout (`python -m benchmark.run` at the repo root) without requiring
# `pip install -e .` first.
_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.exists() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

__all__ = ["models", "loader", "matcher", "metrics", "storage"]
