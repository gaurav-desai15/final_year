from unittest.mock import MagicMock

import pytest

from cpgvd.context_extractor import ContextExtractor
from cpgvd.rules import load_rules

HANDLE_FULL_NAME = "app.py:<module>.handle_request"
INDEX_FULL_NAME = "app.py:<module>.index"

METHODS_JSON = [
    {
        "id": 1,
        "name": "handle_request",
        "fullName": HANDLE_FULL_NAME,
        "filename": "app.py",
        "lineNumber": 9,
        "lineNumberEnd": 11,
        "parameters": ["cmd"],
        "returnType": "ANY",
    },
    {
        "id": 2,
        "name": "index",
        "fullName": INDEX_FULL_NAME,
        "filename": "app.py",
        "lineNumber": 1,
        "lineNumberEnd": 6,
        "parameters": [],
        "returnType": "ANY",
    },
]

CALLS_JSON = [
    {
        "id": 100,
        "name": "system",
        "code": "os.system(cmd)",
        "filename": "app.py",
        "lineNumber": 11,
        "calleeFullName": "os.py:<module>.system",
        "containingMethodFullName": HANDLE_FULL_NAME,
    },
    {
        "id": 101,
        "name": "get",
        "code": "request.args.get('cmd')",
        "filename": "app.py",
        "lineNumber": 3,
        "calleeFullName": "flask.py:<module>.args.get",
        "containingMethodFullName": INDEX_FULL_NAME,
    },
    {
        "id": 102,
        "name": "handle_request",
        "code": "handle_request(cmd)",
        "filename": "app.py",
        "lineNumber": 5,
        "calleeFullName": HANDLE_FULL_NAME,
        "containingMethodFullName": INDEX_FULL_NAME,
    },
]

APP_PY_SOURCE = """\
def index():
    from flask import request
    cmd = request.args.get('cmd')
    if cmd:
        handle_request(cmd)
    return "ok"


def handle_request(cmd):
    import os
    os.system(cmd)
""".splitlines()
# 1-indexed line numbers referenced by the fixtures above:
#   1: def index():
#   3:     cmd = request.args.get('cmd')
#   5:         handle_request(cmd)
#   9: def handle_request(cmd):
#  11:     os.system(cmd)


@pytest.fixture
def repo_root(tmp_path):
    (tmp_path / "app.py").write_text("\n".join(APP_PY_SOURCE) + "\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def rules():
    return load_rules()


def make_client(extra_side_effects=None):
    client = MagicMock()
    effects = [METHODS_JSON, CALLS_JSON]
    if extra_side_effects:
        effects.extend(extra_side_effects)
    client.run_json.side_effect = effects
    return client


def test_load_populates_methods_and_calls(repo_root, rules):
    client = make_client()
    extractor = ContextExtractor(client, repo_root, rules)
    extractor.load()

    assert len(extractor.methods) == 2
    assert len(extractor.calls) == 3
    assert extractor.method_by_full_name(HANDLE_FULL_NAME) is not None


def test_find_sink_candidates_matches_os_system(repo_root, rules):
    client = make_client()
    extractor = ContextExtractor(client, repo_root, rules)
    extractor.load()

    candidates = extractor.find_sink_candidates("python")
    assert HANDLE_FULL_NAME in candidates
    hits = candidates[HANDLE_FULL_NAME]
    assert len(hits) == 1
    assert hits[0].category == "OS Command Injection"
    assert hits[0].cwe == "CWE-78"


def test_find_source_calls_matches_flask_request(repo_root, rules):
    client = make_client()
    extractor = ContextExtractor(client, repo_root, rules)
    extractor.load()

    sources = extractor.find_source_calls("python")
    assert any("request.args.get" in c.code for c in sources)


def test_callers_and_callees_graph(repo_root, rules):
    client = make_client()
    extractor = ContextExtractor(client, repo_root, rules)
    extractor.load()

    callers = extractor.callers_of(HANDLE_FULL_NAME)
    assert [m.full_name for m in callers] == [INDEX_FULL_NAME]

    callees = extractor.callees_of(INDEX_FULL_NAME)
    assert HANDLE_FULL_NAME in [m.full_name for m in callees]


def test_read_source_extracts_correct_lines(repo_root, rules):
    client = make_client()
    extractor = ContextExtractor(client, repo_root, rules)
    extractor.load()

    text = extractor.read_source("app.py", 9, 11)
    assert "def handle_request(cmd):" in text
    assert "os.system(cmd)" in text


def test_build_function_context_without_dataflow(repo_root, rules):
    client = make_client()
    extractor = ContextExtractor(client, repo_root, rules)
    extractor.load()

    method = extractor.method_by_full_name(HANDLE_FULL_NAME)
    hits = extractor.find_sink_candidates("python")[HANDLE_FULL_NAME]
    sources = extractor.find_source_calls("python")

    ctx = extractor.build_function_context(method, "python", hits, sources, include_dataflow=False)

    assert ctx.full_name == HANDLE_FULL_NAME
    assert "os.system(cmd)" in ctx.code
    assert len(ctx.callers) == 1
    assert ctx.callers[0].name == INDEX_FULL_NAME
    assert ctx.matched_sink_patterns
    assert ctx.data_flow_paths == []


def test_build_function_context_with_dataflow(repo_root, rules):
    dataflow_response = [
        [
            {"code": "request.args.get('cmd')", "lineNumber": 3, "filename": "app.py", "method": INDEX_FULL_NAME},
            {"code": "os.system(cmd)", "lineNumber": 11, "filename": "app.py", "method": HANDLE_FULL_NAME},
        ]
    ]
    client = make_client(extra_side_effects=[dataflow_response])
    extractor = ContextExtractor(client, repo_root, rules)
    extractor.load()

    method = extractor.method_by_full_name(HANDLE_FULL_NAME)
    hits = extractor.find_sink_candidates("python")[HANDLE_FULL_NAME]
    sources = extractor.find_source_calls("python")

    ctx = extractor.build_function_context(method, "python", hits, sources, include_dataflow=True)

    assert len(ctx.data_flow_paths) == 1
    assert len(ctx.data_flow_paths[0].steps) == 2
    assert ctx.data_flow_paths[0].steps[0].code == "request.args.get('cmd')"
