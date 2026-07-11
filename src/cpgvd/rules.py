"""Loads the sink/source regex rules used to shortlist candidate functions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "sinks_sources.yaml"


@dataclass
class Rule:
    pattern: re.Pattern
    category: str
    cwe: str = ""
    raw_pattern: str = ""


@dataclass
class LanguageRules:
    sinks: list[Rule]
    sources: list[Rule]


def load_rules(path: Path | None = None) -> dict[str, LanguageRules]:
    path = path or DEFAULT_RULES_PATH
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    rules: dict[str, LanguageRules] = {}
    for lang, section in raw.items():
        sinks = [_build_rule(r) for r in section.get("sinks", [])]
        sources = [_build_rule(r) for r in section.get("sources", [])]
        rules[lang] = LanguageRules(sinks=sinks, sources=sources)
    return rules


def _build_rule(entry: dict) -> Rule:
    pattern = entry["pattern"]
    return Rule(
        pattern=re.compile(pattern),
        category=entry.get("category", "Unknown"),
        cwe=entry.get("cwe", ""),
        raw_pattern=pattern,
    )
