"""Mutation harness for the control-absence evaluation.

Real Node/Express apps that *have* working access controls are turned into
labelled positives by programmatically removing one control at a time. Because
each removal is scripted, the ground truth is exact -- file, line range, route
path and control class -- with no human judgement in the label.

Five operators, matching the plan's M1-M5:

    M1  drop an auth-middleware argument from a route registration
    M2  drop an ownership comparison (`if (doc.ownerId !== req.user.id) ...`)
    M3  drop a role / privilege check (`if (!req.user.isAdmin) ...`)
    M4  drop a session validation (`if (!req.session.user) ...`)
    M5  drop an input-validation guard sitting before a write

Matching is regex / brace-balanced text, not an AST: the operators are
deliberately narrow (a curated guard vocabulary, a denial-shaped body) so the
mutations they emit are high-confidence, and every mutant is run through
`node --check` before it counts. This vocabulary is kept SEPARATE from
`rules/control_absence.yaml` on purpose -- the mutator and the detector must
not share pattern definitions or the evaluation is circular.

The mutation is line-count preserving: removed lines become blank, so a
record's `start_line`/`end_line` are valid against both the original file and
the mutant, which keeps scoring findings against labels trivial.
"""

from __future__ import annotations

import logging
import re
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .models import MutationRecord

logger = logging.getLogger(__name__)

_SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "public",
    "__tests__",
    "test",
    "tests",
    "spec",
}
_JS_SUFFIXES = {".js", ".mjs", ".cjs"}
_SKIP_FILE_RE = re.compile(r"\.(test|spec|min|bundle)\.[cm]?js$")

# -- guard vocabularies (mutator-local; NOT shared with the detector) --------

_PASSPORT_AUTH_RE = re.compile(r"passport\s*\.\s*authenticate\s*\(")

# Route-middleware classifiers, matched against the argument (and its last
# `.`-segment). Ordered validation -> authorization -> authentication.
_MW_VALIDATION_RE = re.compile(
    r"^(?:validate|validator|validation|celebrate|checkschema|sanitize|schemavalidator|runvalidation)\w*",
    re.IGNORECASE,
)
_MW_AUTHZ_RE = re.compile(
    r"^(?:authoriz|restrictto|restrict$|restrict\b|is_?admin|ensure_?admin|require_?admin|admin_?only"
    r"|has_?role|check_?role|require_?role|role_?required|has_?permission|check_?permission"
    r"|require_?permission|grant_?access|\bacl\b|\brbac\b|permit\b|check_?abilities|allow_?for"
    r"|only_?admin|is_?authorized)",
    re.IGNORECASE,
)
_MW_AUTHN_RE = re.compile(
    r"^(?:auth$|auth\b|authenticat|require_?(?:auth|login|user|s?login)|ensure_?(?:auth|logged_?in|authenticated)"
    r"|is_?(?:auth|logged_?in|authenticated)|check_?auth|verify_?(?:token|jwt|auth|user)"
    r"|jwt_?(?:auth|guard|verify)|login_?required|needs_?auth|protect|secured|with_?auth"
    r"|check_?(?:jwt|token)|bearer|token_?required|must_?be_?logged_?in)",
    re.IGNORECASE,
)

_OWNERSHIP_RE = re.compile(
    r"(?:req\s*\.\s*user|currentuser|loggeduser)"
    r".{0,80}?(?:owner|ownerid|userid|authorid|createdby|author|_id|\bid\b)"
    r"|(?:owner|ownerid|userid|authorid|createdby)\b.{0,80}?req\s*\.\s*user",
    re.IGNORECASE | re.DOTALL,
)
_ROLE_RE = re.compile(
    r"\bis_?admin\b|\.role\b|hasrole|has_?permission|\.admin\b|issuperuser|is_?staff"
    r"|privilege|\brole\s*(?:===|!==|==|!=)|\bcan\s*\(|\bability\b|accesslevel|permissions?\b",
    re.IGNORECASE,
)
_SESSION_RE = re.compile(
    r"req\s*\.\s*session|req\s*\.\s*isauthenticated\s*\(\s*\)|\bsession\s*\.\s*(?:user|userid|uid)\b",
    re.IGNORECASE,
)
# A denial-shaped `if` body: bounce the request rather than continue. A bare
# `return` counts, but NOT `return Promise.resolve()` / `return true` / `next()`
# -- those are "grant" branches (removing them makes the code fail closed, so
# it isn't a valid "removed a control" positive).
_DENIAL_RE = re.compile(
    r"\breturn\b(?!\s*(?:promise\s*\.\s*resolve|resolve\s*\(|true\b|next\s*\(\s*\)))"
    r"|\bthrow\b|res\s*\.\s*(?:status\s*\(\s*4\d\d|sendstatus\s*\(\s*4\d\d|redirect|render\s*\(\s*['\"]login)"
    r"|next\s*\(\s*(?:new\s+)?\w*error|\bunauthorized\b|\bforbidden\b",
    re.IGNORECASE,
)

_VALIDATOR_RE = re.compile(
    r"req\s*\.\s*(?:check|assert|sanitize)(?:body|params|query)?\s*\("
    r"|validationresult\s*\(|\.\s*validate(?:async)?\s*\(|joi\s*\.|\.\s*isempty\s*\(\s*\)"
    r"|schema\s*\.\s*parse\s*\(|matcheddata\s*\(|celebrate\s*\(|check\s*\(\s*['\"]",
    re.IGNORECASE,
)
_DB_WRITE_RE = re.compile(
    r"\.\s*(?:insertone|insertmany|insert|updateone|updatemany|update|replaceone|deleteone|"
    r"deletemany|remove|save|create|findoneandupdate|findoneanddelete|bulkwrite)\s*\(",
    re.IGNORECASE,
)
_ROUTE_REG_RE = re.compile(
    r"\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(",
    re.IGNORECASE,
)


@dataclass
class _Target:
    operator: str
    control_class: str
    start_line: int  # 1-indexed, inclusive
    end_line: int
    original: str
    mutated: str
    route_path: str = ""
    note: str = ""


# -- brace / paren matching -------------------------------------------------


def _match_balanced(text: str, open_idx: int, opener: str, closer: str) -> int:
    """Index just past the matching `closer` for the `opener` at `open_idx`.

    Skips over string / template / comment content. Returns -1 if unbalanced.
    """
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c in "\"'`":
            i = _skip_string(text, i)
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i)
            i = n if nl == -1 else nl
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _skip_string(text: str, i: int) -> int:
    quote = text[i]
    i += 1
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return n


def _split_top_level_commas(arg_text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    cur = []
    i = 0
    n = len(arg_text)
    while i < n:
        c = arg_text[i]
        if c in "\"'`":
            j = _skip_string(arg_text, i)
            cur.append(arg_text[i:j])
            i = j
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if cur:
        parts.append("".join(cur))
    return parts


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _line_end_offset(text: str, line: int) -> int:
    """Offset of the newline ending 1-indexed `line` (or len(text) if last)."""
    nl = -1
    for _ in range(line):
        nl = text.find("\n", nl + 1)
        if nl == -1:
            return len(text)
    return nl


def _blank_span(lines: list[str], start_line: int, end_line: int) -> str:
    """The replacement text for a removed span: same number of lines, empty."""
    return "\n".join("" for _ in range(end_line - start_line + 1))


# -- operators -------------------------------------------------------------


def _iter_if_statements(text: str) -> Iterator[tuple[int, int, str, str]]:
    """Yield (cond_start, stmt_end, condition, body) for each `if (...)` ..."""
    for m in re.finditer(r"\bif\s*\(", text):
        paren_open = text.index("(", m.start())
        cond_end = _match_balanced(text, paren_open, "(", ")")
        if cond_end == -1:
            continue
        condition = text[paren_open + 1 : cond_end - 1]
        j = cond_end
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        if j >= len(text):
            continue
        if text[j] == "{":
            body_end = _match_balanced(text, j, "{", "}")
            if body_end == -1:
                continue
            body = text[j:body_end]
            stmt_end = body_end
        else:
            semi = text.find(";", j)
            nl = text.find("\n", j)
            stmt_end = semi + 1 if semi != -1 and (nl == -1 or semi < nl) else (nl if nl != -1 else len(text))
            body = text[j:stmt_end]
        yield m.start(), stmt_end, condition, body


def _guard_if_operators(text: str, lines: list[str]) -> Iterator[_Target]:
    """M2 / M3 / M4: an access-control `if` whose body denies the request."""
    for start, end, condition, body in _iter_if_statements(text):
        if not _DENIAL_RE.search(body):
            continue
        if _OWNERSHIP_RE.search(condition):
            operator, control = "M2", "ownership"
        elif _ROLE_RE.search(condition):
            operator, control = "M3", "authorization"
        elif _SESSION_RE.search(condition):
            operator, control = "M4", "session"
        else:
            continue
        s_line = _line_of(text, start)
        e_line = _line_of(text, end - 1)
        original = "\n".join(lines[s_line - 1 : e_line])
        yield _Target(
            operator=operator,
            control_class=control,
            start_line=s_line,
            end_line=e_line,
            original=original,
            mutated=_blank_span(lines, s_line, e_line),
            note=f"removed {control} check: if ({condition.strip()[:80]})",
        )


def _nth_top_level_comma(arg_text: str, n: int) -> int:
    """Offset of the n-th (0-indexed) top-level comma in `arg_text`, or -1."""
    depth = 0
    seen = 0
    i = 0
    while i < len(arg_text):
        c = arg_text[i]
        if c in "\"'`":
            i = _skip_string(arg_text, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            if seen == n:
                return i
            seen += 1
        i += 1
    return -1


def _drop_auth_middleware(text: str, lines: list[str]) -> Iterator[_Target]:
    """M1: remove ONE access-control middleware argument from a route
    registration. One mutation per removable middleware, classified by name
    (an auth middleware -> authentication, an admin/role one -> authorization).
    The handler (last arg) and path (first arg) are never touched, and only
    the prefix up to the handler is rewritten so an inline-function handler
    body is left byte-for-byte intact."""
    for m in _ROUTE_REG_RE.finditer(text):
        paren_open = text.index("(", m.start())
        call_end = _match_balanced(text, paren_open, "(", ")")
        if call_end == -1:
            continue
        arg_text = text[paren_open + 1 : call_end - 1]
        args = _split_top_level_commas(arg_text)
        if len(args) < 3:  # need path, >=1 middleware, handler
            continue
        route_path = ""
        pm = re.match(r"\s*['\"]([^'\"]+)['\"]", args[0])
        if pm:
            route_path = pm.group(1)

        handler_comma = _nth_top_level_comma(arg_text, len(args) - 2)
        if handler_comma == -1:
            continue
        handler_start = paren_open + 1 + handler_comma + 1  # just past that comma
        line_start = text.rfind("\n", 0, m.start()) + 1
        s_line = _line_of(text, m.start())
        e_line = _line_of(text, handler_start - 1)
        line_end = len(text) if e_line > len(lines) else _line_end_offset(text, e_line)
        head = text[line_start : paren_open + 1]
        tail = text[handler_start:line_end]  # the handler arg + rest of that line

        for k, mw in enumerate(args[1:-1], start=1):
            classified = _classify_middleware(mw)
            if classified is None:
                continue
            operator, control = classified
            kept = [a.strip() for i, a in enumerate(args[:-1]) if i != k]
            new_region = head + ", ".join(kept) + ", " + tail.lstrip()
            pad = (e_line - s_line) - new_region.count("\n")
            mutated = new_region + ("\n" * pad if pad > 0 else "")
            yield _Target(
                operator=operator,
                control_class=control,
                start_line=s_line,
                end_line=e_line,
                original="\n".join(lines[s_line - 1 : e_line]),
                mutated=mutated,
                route_path=route_path,
                note=f"dropped route middleware: {mw.strip()[:80]}",
            )


def _classify_middleware(arg: str) -> tuple[str, str] | None:
    """(operator, control_class) for a route-middleware argument, or None.

    Handles the common shapes: a bare name (`requireAuth`), a call
    (`auth('getUsers')`, `authorize(['admin'])`), and an object member
    (`mw.isLoggedIn`, `middleware.protect`).
    """
    a = arg.strip()
    if not a or _looks_like_handler(a):
        return None
    if _PASSPORT_AUTH_RE.search(a):
        return ("M1", "authentication")
    candidates = [a, a.split(".")[-1].strip()]
    for cand in candidates:
        if _MW_VALIDATION_RE.match(cand):
            return ("M5", "validation")
    for cand in candidates:
        if _MW_AUTHZ_RE.match(cand):
            return ("M1", "authorization")
    for cand in candidates:
        if _MW_AUTHN_RE.match(cand):
            return ("M1", "authentication")
    return None


def _looks_like_handler(arg: str) -> bool:
    """A `(req, res) => ...` or `function (req, res)` inline handler passed
    mid-list -- not a middleware we should drop."""
    a = arg.strip()
    return bool(
        re.match(r"^(?:async\s+)?function\b", a)
        or re.match(r"^\([^)]*\)\s*=>", a)
        or re.match(r"^\w+\s*=>", a)
    )


def _drop_validation_before_write(text: str, lines: list[str]) -> Iterator[_Target]:
    """M5: remove a validation guard that sits above a DB write in the same file."""
    write_lines = [_line_of(text, m.start()) for m in _DB_WRITE_RE.finditer(text)]
    if not write_lines:
        return
    seen_spans: set[tuple[int, int]] = set()

    # (a) validator-check `if` blocks
    for start, end, condition, body in _iter_if_statements(text):
        if not _VALIDATOR_RE.search(condition) and "errors" not in condition.lower():
            continue
        if not _DENIAL_RE.search(body):
            continue
        s_line = _line_of(text, start)
        e_line = _line_of(text, end - 1)
        if not any(s_line < wl <= s_line + 60 for wl in write_lines):
            continue
        if (s_line, e_line) in seen_spans:
            continue
        seen_spans.add((s_line, e_line))
        yield _Target(
            operator="M5",
            control_class="validation",
            start_line=s_line,
            end_line=e_line,
            original="\n".join(lines[s_line - 1 : e_line]),
            mutated=_blank_span(lines, s_line, e_line),
            note="removed validation-error guard before a write",
        )

    # (b) standalone validator call statements
    for m in _VALIDATOR_RE.finditer(text):
        line_no = _line_of(text, m.start())
        if not any(line_no < wl <= line_no + 60 for wl in write_lines):
            continue
        raw = lines[line_no - 1]
        if "if" in raw.split("(")[0]:  # already handled as an if-block
            continue
        if (line_no, line_no) in seen_spans:
            continue
        seen_spans.add((line_no, line_no))
        yield _Target(
            operator="M5",
            control_class="validation",
            start_line=line_no,
            end_line=line_no,
            original=raw,
            mutated="",
            note="removed validator call before a write",
        )


_OPERATORS = (_drop_auth_middleware, _guard_if_operators, _drop_validation_before_write)


# -- file / repo driving --------------------------------------------------


def iter_source_files(repo_path: Path) -> Iterator[Path]:
    for path in sorted(repo_path.rglob("*")):
        if path.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(repo_path).parts):
            continue
        if path.suffix not in _JS_SUFFIXES or _SKIP_FILE_RE.search(path.name):
            continue
        yield path


def find_file_mutations(path: Path, rel: str, app: str) -> list[MutationRecord]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.split("\n")
    records: list[MutationRecord] = []
    claimed: list[tuple[str, int, int]] = []
    for op in _OPERATORS:
        for t in op(text, lines):
            # one mutation per line span *across different operators* -- M1 may
            # legitimately emit several mutations on the same registration line.
            if any(
                cop != t.operator and a <= t.end_line and t.start_line <= b
                for cop, a, b in claimed
            ):
                continue
            claimed.append((t.operator, t.start_line, t.end_line))
            records.append(
                MutationRecord(
                    id=f"{app}::{t.operator}::{rel}::{t.start_line}",
                    app=app,
                    operator=t.operator,
                    control_class=t.control_class,
                    file=rel,
                    start_line=t.start_line,
                    end_line=t.end_line,
                    route_path=t.route_path,
                    original_text=t.original,
                    mutated_text=t.mutated,
                    note=t.note,
                )
            )
    return records


def find_mutations(repo_path: Path, app: str, *, commit_sha: str = "", repo: str = "") -> list[MutationRecord]:
    repo_path = Path(repo_path)
    out: list[MutationRecord] = []
    for path in iter_source_files(repo_path):
        rel = path.relative_to(repo_path).as_posix()
        for rec in find_file_mutations(path, rel, app):
            rec.commit_sha = commit_sha
            rec.repo = repo
            out.append(rec)
    return out


def _mutate_text(original_file_text: str, rec: MutationRecord) -> str:
    lines = original_file_text.split("\n")
    if rec.original_text != "\n".join(lines[rec.start_line - 1 : rec.end_line]):
        raise ValueError(f"{rec.id}: original text no longer matches the file at that span")
    replacement = rec.mutated_text.split("\n")
    lines[rec.start_line - 1 : rec.end_line] = replacement
    return "\n".join(lines)


@contextmanager
def mutation_applied(repo_path: Path, rec: MutationRecord) -> Iterator[Path]:
    """Apply `rec` to its file in place for the duration of the block, then
    restore the exact original bytes."""
    target = Path(repo_path) / rec.file
    original = target.read_text(encoding="utf-8")
    try:
        target.write_text(_mutate_text(original, rec), encoding="utf-8")
        yield target
    finally:
        target.write_text(original, encoding="utf-8")


def node_check(path: Path) -> tuple[bool, str]:
    """Run `node --check` on a file. Returns (ok, stderr)."""
    try:
        proc = subprocess.run(
            ["node", "--check", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"node --check unavailable: {e}"
    return proc.returncode == 0, proc.stderr.strip()


def verify_mutations(repo_path: Path, records: list[MutationRecord]) -> list[MutationRecord]:
    """Keep only mutations whose mutant file still parses (`node --check`)."""
    repo_path = Path(repo_path)
    kept: list[MutationRecord] = []
    for rec in records:
        try:
            with mutation_applied(repo_path, rec) as target:
                ok, err = node_check(target)
        except (OSError, ValueError) as e:
            logger.warning("mutation %s could not be applied: %s", rec.id, e)
            continue
        if ok:
            kept.append(rec)
        else:
            logger.info("mutation %s dropped: mutant does not parse (%s)", rec.id, err.splitlines()[0] if err else "?")
    return kept
