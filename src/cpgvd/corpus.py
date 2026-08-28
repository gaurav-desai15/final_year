"""Mutation-corpus bookkeeping: label I/O and the train/held-out split.

The corpus is a set of real Node/Express apps, each mutated by `mutation.py`
into many labelled missing-control instances. Labels are stored as JSONL (one
`MutationRecord` per line) so a run can stream them and so `git diff` on the
corpus stays readable.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path

from .models import MutationRecord


def write_labels(records: list[MutationRecord], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(rec.model_dump_json() + "\n")
    return path


def read_labels(path: Path) -> list[MutationRecord]:
    records: list[MutationRecord] = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(MutationRecord.model_validate_json(line))
    return records


def _app_bucket(app: str, holdout_frac: float, seed: str) -> bool:
    """Stable hash -> True if `app` is in the held-out set. Deterministic across
    runs and independent of corpus order, so re-collecting apps never reshuffles
    an app between train and held-out."""
    h = hashlib.sha256(f"{seed}:{app}".encode()).digest()
    frac = int.from_bytes(h[:8], "big") / 2**64
    return frac < holdout_frac


def split_by_app(
    records: list[MutationRecord],
    holdout_frac: float = 0.3,
    seed: str = "cpgvd-corpus-v1",
) -> tuple[list[MutationRecord], list[MutationRecord]]:
    """Split records into (train, holdout) BY APPLICATION.

    Splitting by mutation would leak: mutations from one app share almost all
    their code. Every mutation of a given app lands on the same side.
    """
    train, holdout = [], []
    for rec in records:
        (holdout if _app_bucket(rec.app, holdout_frac, seed) else train).append(rec)
    return train, holdout


def summarize(records: list[MutationRecord]) -> dict:
    by_app: dict[str, int] = defaultdict(int)
    by_operator: dict[str, int] = defaultdict(int)
    by_control: dict[str, int] = defaultdict(int)
    for rec in records:
        by_app[rec.app] += 1
        by_operator[rec.operator] += 1
        by_control[rec.control_class] += 1
    return {
        "instances": len(records),
        "apps": len(by_app),
        "by_operator": dict(sorted(by_operator.items())),
        "by_control_class": dict(sorted(by_control.items())),
        "per_app": dict(sorted(by_app.items())),
    }


def summarize_json(records: list[MutationRecord]) -> str:
    return json.dumps(summarize(records), indent=2)
