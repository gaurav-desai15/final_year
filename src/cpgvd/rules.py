"""Loads the sink/source regex rules used to shortlist candidate functions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"
DEFAULT_RULES_PATH = _RULES_DIR / "sinks_sources.yaml"
DEFAULT_ABSENCE_RULES_PATH = _RULES_DIR / "control_absence.yaml"
DEFAULT_HYGIENE_RULES_PATH = _RULES_DIR / "hygiene.yaml"


@dataclass
class Rule:
    pattern: re.Pattern
    category: str
    cwe: str = ""
    raw_pattern: str = ""
    severity: str = ""  # hygiene checks carry a severity hint; sinks leave this blank


@dataclass
class LanguageRules:
    sinks: list[Rule]
    sources: list[Rule]


@dataclass
class ControlRule:
    """A rule for the control-absence mode: either a `trigger` (an operation
    needing a control) or a `guard` (evidence a control is present)."""

    pattern: re.Pattern
    category: str
    kind: str  # "trigger" or "guard"
    operation: str = ""  # trigger only: route | db_read | db_write | file_send | credential | session
    control: str = ""  # guard only: authentication | authorization | ownership | session | validation
    raw_pattern: str = ""


@dataclass
class AbsenceRules:
    triggers: list[ControlRule]
    guards: list[ControlRule]


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
        severity=entry.get("severity", ""),
    )


def load_hygiene_rules(path: Path | None = None) -> dict[str, list[Rule]]:
    """Load `--mode hygiene` checks: per-language lists of 'dangerous pattern
    present' regexes (weak crypto, disabled TLS, hardcoded secrets, debug
    flags). Same `Rule` shape as sinks, plus a `severity` hint."""
    path = path or DEFAULT_HYGIENE_RULES_PATH
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return {
        lang: [_build_rule(r) for r in (section or {}).get("checks", [])]
        for lang, section in raw.items()
    }


def load_absence_rules(path: Path | None = None) -> dict[str, AbsenceRules]:
    path = path or DEFAULT_ABSENCE_RULES_PATH
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    rules: dict[str, AbsenceRules] = {}
    for lang, section in raw.items():
        triggers = [_build_control_rule(r, "trigger") for r in section.get("triggers", [])]
        guards = [_build_control_rule(r, "guard") for r in section.get("guards", [])]
        rules[lang] = AbsenceRules(triggers=triggers, guards=guards)
    return rules


def _build_control_rule(entry: dict, kind: str) -> ControlRule:
    pattern = entry["pattern"]
    return ControlRule(
        pattern=re.compile(pattern),
        category=entry.get("category", "Unknown"),
        kind=kind,
        operation=entry.get("operation", ""),
        control=entry.get("control", ""),
        raw_pattern=pattern,
    )
