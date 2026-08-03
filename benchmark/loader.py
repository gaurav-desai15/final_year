"""Loads benchmark datasets from YAML.

A dataset file is data, not code, so adding a new benchmark suite means
dropping a `.yaml` into `benchmark/datasets/` -- no Python changes. See
`docs/benchmarking.md` for the schema.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

import yaml
from pydantic import ValidationError

from .models import BenchmarkCase, Dataset, GroundTruth

logger = logging.getLogger(__name__)

DATASETS_DIR = Path(__file__).parent / "datasets"
REPO_ROOT = Path(__file__).resolve().parent.parent


class DatasetError(RuntimeError):
    """Raised when a dataset file is missing or structurally invalid."""


def _auto_ids(entries: Iterable[dict[str, Any]], case_id: str) -> list[dict[str, Any]]:
    """Give every ground-truth entry a stable id if the author omitted one.

    Ids matter: comparison between runs is keyed on them, so an entry that
    silently changes id would look like one vulnerability disappearing and
    another appearing.
    """
    result = []
    for index, entry in enumerate(entries, start=1):
        entry = dict(entry)
        entry.setdefault("id", f"{case_id}-gt{index}")
        result.append(entry)
    return result


def load_dataset(path: Path) -> Dataset:
    """Parse one dataset YAML file into a `Dataset`."""
    path = Path(path)
    if not path.exists():
        raise DatasetError(f"Dataset file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise DatasetError(f"{path.name}: invalid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise DatasetError(f"{path.name}: top level must be a mapping")

    raw.setdefault("name", path.stem)
    default_language = raw.get("default_language", "")
    default_args = raw.get("default_analyze_args", []) or []

    cases: list[BenchmarkCase] = []
    for index, case_raw in enumerate(raw.pop("cases", []) or [], start=1):
        if not isinstance(case_raw, dict):
            raise DatasetError(f"{path.name}: case #{index} must be a mapping")
        case_raw = dict(case_raw)
        case_raw.setdefault("id", f"{raw['name']}-case{index}")
        case_raw.setdefault("language", default_language)
        if not case_raw.get("analyze_args"):
            case_raw["analyze_args"] = list(default_args)
        case_raw["expected"] = [
            GroundTruth(**entry)
            for entry in _auto_ids(case_raw.get("expected", []) or [], case_raw["id"])
        ]
        try:
            cases.append(BenchmarkCase(**case_raw))
        except ValidationError as exc:
            raise DatasetError(f"{path.name}: case '{case_raw['id']}' is invalid: {exc}") from exc

    try:
        dataset = Dataset(cases=cases, **raw)
    except ValidationError as exc:
        raise DatasetError(f"{path.name}: invalid dataset: {exc}") from exc

    _validate_unique_ids(dataset, path)
    return dataset


def _validate_unique_ids(dataset: Dataset, path: Path) -> None:
    seen_cases: set[str] = set()
    for case in dataset.cases:
        if case.id in seen_cases:
            raise DatasetError(f"{path.name}: duplicate case id '{case.id}'")
        seen_cases.add(case.id)
        seen_gt: set[str] = set()
        for gt in case.expected:
            if gt.id in seen_gt:
                raise DatasetError(
                    f"{path.name}: duplicate ground-truth id '{gt.id}' in case '{case.id}'"
                )
            seen_gt.add(gt.id)


def discover_datasets(directory: Path | None = None) -> list[Path]:
    """All dataset files in `directory`, sorted for deterministic run order."""
    directory = Path(directory) if directory else DATASETS_DIR
    if not directory.exists():
        return []
    return sorted(p for p in directory.iterdir() if p.suffix in {".yaml", ".yml"})


def load_datasets(
    names: list[str] | None = None, directory: Path | None = None
) -> list[Dataset]:
    """Load datasets by name (file stem), or every dataset when `names` is None."""
    directory = Path(directory) if directory else DATASETS_DIR
    available = {p.stem: p for p in discover_datasets(directory)}

    if names:
        missing = [n for n in names if n not in available]
        if missing:
            raise DatasetError(
                f"Unknown dataset(s): {', '.join(missing)}. "
                f"Available: {', '.join(sorted(available)) or '(none)'}"
            )
        paths = [available[n] for n in names]
    else:
        paths = list(available.values())

    return [load_dataset(p) for p in paths]


def resolve_repo(repo: str) -> str:
    """Turn a dataset's `repo` field into something `cpgvd analyze` accepts.

    URLs pass through untouched; relative paths resolve against the project
    root so a dataset works regardless of the caller's working directory.
    """
    if repo.startswith(("http://", "https://", "git@", "ssh://")):
        return repo
    path = Path(repo)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return str(path)
