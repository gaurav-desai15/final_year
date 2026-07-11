"""Thin wrapper around `cpgqls-client` for talking to a running Joern
CPGQL server: loading a CPG and running Scala queries that return JSON.

Joern's CPGQL server is a stateful Scala REPL over HTTP -- each `execute()`
call runs one query in the same session, so state (like the loaded CPG, or
helper `def`s) persists across calls. We exploit that: once per session we
define a small `cpgvdEscape` helper, then every subsequent query builds its
own JSON string server-side (via string concatenation) so we get structured
data back instead of trying to parse Scala's pretty-printed case-class
output.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from cpgqls_client import CPGQLSClient

logger = logging.getLogger(__name__)

_ESCAPE_HELPER = (
    "def cpgvdEscape(s: String): String = if (s == null) \"\" else "
    "s.replace(\"\\\\\", \"\\\\\\\\\").replace(\"\\\"\", \"\\\\\\\"\")"
    ".replace(\"\\n\", \"\\\\n\").replace(\"\\r\", \"\\\\r\").replace(\"\\t\", \"\\\\t\")"
)

_RESULT_RE = re.compile(r"=\s*\"(.*)\"\s*\Z", re.DOTALL)


class CpgQueryError(RuntimeError):
    def __init__(self, query: str, stdout: str, stderr: str):
        self.query = query
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"CPGQL query failed.\nquery: {query}\nstdout: {stdout}\nstderr: {stderr}")


def _unescape(raw: str) -> str:
    """Reverse the escaping applied by the Scala-side `cpgvdEscape` helper."""
    mapping = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "r": "\r"}
    out: list[str] = []
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == "\\" and i + 1 < len(raw) and raw[i + 1] in mapping:
            out.append(mapping[raw[i + 1]])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


class CpgClient:
    """Executes CPGQL queries against a running Joern server and parses
    the JSON-producing query pattern used throughout `context_extractor.py`.
    """

    def __init__(self, host: str, port: int):
        self._client = CPGQLSClient(f"{host}:{port}")
        self._ready = False

    def _execute(self, query: str) -> dict[str, Any]:
        logger.debug("CPGQL >>> %s", query[:500])
        result = self._client.execute(query)
        if not result.get("success", True):
            raise CpgQueryError(query, result.get("stdout", ""), result.get("stderr", ""))
        return result

    def load_cpg(self, cpg_path: Path) -> None:
        """Import a pre-built CPG (`cpg.bin`) into the server session."""
        # Built by hand (not the cpgqls_client helper, which targets
        # importing raw source directories) since we already have a
        # pre-parsed cpg.bin from `joern-parse`.
        escaped_path = str(cpg_path).replace("\\", "\\\\").replace('"', '\\"')
        self._execute(f'importCpg("{escaped_path}")')
        self._execute(_ESCAPE_HELPER)
        self._ready = True

    def run_raw(self, query: str) -> str:
        """Run a query, return the raw `stdout` text Joern printed."""
        return self._execute(query).get("stdout", "")

    def run_json(self, scala_expr: str) -> Any:
        """Run a Scala expression that evaluates to a JSON *string* (built
        with `cpgvdEscape`) and return the parsed Python object.

        The expression should evaluate to a `String` containing valid JSON,
        e.g. `cpg.method.name.l.mkString("[\\"", "\\",\\"", "\\"]")` or the
        richer per-node JSON builders in `context_extractor.py`.
        """
        stdout = self.run_raw(scala_expr)
        match = _RESULT_RE.search(stdout)
        if not match:
            raise CpgQueryError(scala_expr, stdout, "could not locate a String result to parse")
        unescaped = _unescape(match.group(1))
        try:
            return json.loads(unescaped)
        except json.JSONDecodeError as e:
            raise CpgQueryError(scala_expr, stdout, f"JSON decode failed: {e}") from e
