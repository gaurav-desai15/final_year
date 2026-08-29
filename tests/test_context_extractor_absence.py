"""Control-absence mode: trigger detection, guard-evidence collection,
and absence-context assembly. JS fixtures modelled on an Express app."""

from unittest.mock import MagicMock

import pytest

from cpgvd.context_extractor import ContextExtractor
from cpgvd.rules import load_absence_rules, load_rules

ADMIN_HANDLER = "routes.js:adminHandler"
PROFILE_HANDLER = "routes.js:profileHandler"
REGISTER_ADMIN = "routes.js:<module>"

METHODS_JSON = [
    {
        "id": 1,
        "name": "adminHandler",
        "fullName": ADMIN_HANDLER,
        "filename": "routes.js",
        "lineNumber": 7,
        "lineNumberEnd": 11,
        "parameters": ["req", "res"],
        "returnType": "ANY",
    },
    {
        "id": 2,
        "name": "profileHandler",
        "fullName": PROFILE_HANDLER,
        "filename": "routes.js",
        "lineNumber": 14,
        "lineNumberEnd": 18,
        "parameters": ["req", "res"],
        "returnType": "ANY",
    },
    {
        "id": 3,
        "name": "<module>",
        "fullName": REGISTER_ADMIN,
        "filename": "routes.js",
        "lineNumber": 1,
        "lineNumberEnd": 4,
        "parameters": [],
        "returnType": "ANY",
    },
]

CALLS_JSON = [
    # admin route: NO guard on the registration, NO guard in the handler
    {
        "id": 100,
        "name": "get",
        "code": "app.get('/admin/users', adminHandler)",
        "filename": "routes.js",
        "lineNumber": 2,
        "calleeFullName": "express.get",
        "containingMethodFullName": REGISTER_ADMIN,
    },
    {
        "id": 101,
        "name": "find",
        "code": "usersCol.find({}).toArray(cb)",
        "filename": "routes.js",
        "lineNumber": 8,
        "calleeFullName": "mongo.find",
        "containingMethodFullName": ADMIN_HANDLER,
    },
    # profile route: guarded by requireAuth middleware on the registration
    {
        "id": 102,
        "name": "get",
        "code": "app.get('/profile', requireAuth, profileHandler)",
        "filename": "routes.js",
        "lineNumber": 3,
        "calleeFullName": "express.get",
        "containingMethodFullName": REGISTER_ADMIN,
    },
    {
        "id": 103,
        "name": "findOne",
        "code": "usersCol.findOne({_id: req.user.id})",
        "filename": "routes.js",
        "lineNumber": 15,
        "calleeFullName": "mongo.findOne",
        "containingMethodFullName": PROFILE_HANDLER,
    },
]

ROUTES_JS = """\
function registerRoutes(app) {
    app.get('/admin/users', adminHandler);
    app.get('/profile', requireAuth, profileHandler);
}


function adminHandler(req, res) {
    usersCol.find({}).toArray(function (err, users) {
        res.json(users);
    });
}


function profileHandler(req, res) {
    usersCol.findOne({_id: req.user.id}, function (err, u) {
        res.json(u);
    });
}
"""


def make_client():
    client = MagicMock()
    client.run_json.side_effect = [METHODS_JSON, CALLS_JSON]
    return client


@pytest.fixture
def extractor(tmp_path):
    (tmp_path / "routes.js").write_text(ROUTES_JS, encoding="utf-8")
    ex = ContextExtractor(make_client(), tmp_path, load_rules(), load_absence_rules())
    ex.load()
    return ex


def test_find_control_triggers_flags_route_and_db(extractor):
    triggers = extractor.find_control_triggers("javascript")
    assert ADMIN_HANDLER in triggers
    ops = {h.operation for h in triggers[ADMIN_HANDLER]}
    assert "db_read" in ops
    # the route registration itself is a trigger on the module scope
    assert any(h.operation == "route" and h.route_path == "/admin/users" for h in triggers[REGISTER_ADMIN])


def test_guard_evidence_empty_for_unprotected_admin_handler(extractor):
    method = extractor.method_by_full_name(ADMIN_HANDLER)
    assert extractor.collect_guard_evidence(method, "javascript") == []


def test_guard_evidence_finds_middleware_on_caller(extractor):
    method = extractor.method_by_full_name(PROFILE_HANDLER)
    evidence = extractor.collect_guard_evidence(method, "javascript")
    assert evidence, "requireAuth on the route registration should be picked up"
    controls = {e.control for e in evidence}
    assert "authentication" in controls
    assert any(e.scope == "route-middleware" for e in evidence)


def _route_hit(extractor, path):
    for hits in extractor.find_control_triggers("javascript").values():
        for h in hits:
            if h.operation == "route" and h.route_path == path:
                return h
    raise AssertionError(f"no route hit for {path}")


def test_build_route_absence_context_unprotected_route(extractor):
    ctx = extractor.build_route_absence_context(_route_hit(extractor, "/admin/users"), "javascript")

    assert ctx.context_id.startswith("absence-route:")
    assert ctx.start_line == 2  # the registration line, matches an M1 label
    assert ctx.guard_evidence == []
    assert any(t.operation == "route" and t.route_path == "/admin/users" for t in ctx.control_triggers)
    # the resolved handler body is shown, and its db read surfaces as a trigger
    assert "usersCol.find({})" in ctx.code
    assert any(t.operation == "db_read" for t in ctx.control_triggers)


def test_build_route_absence_context_picks_up_route_middleware(extractor):
    ctx = extractor.build_route_absence_context(_route_hit(extractor, "/profile"), "javascript")

    assert ctx.guard_evidence
    g = ctx.guard_evidence[0]
    assert g.control == "authentication" and g.scope == "route-middleware"
    assert g.node_id >= 0  # anchored on the registration call node


def test_split_call_args_keeps_inline_function_whole():
    from cpgvd.context_extractor import _split_call_args

    args = _split_call_args("app.get('/x', requireAuth, function (req, res) { return res.end(); })")
    assert len(args) == 3
    assert args[0].strip() == "'/x'"
    assert args[1].strip() == "requireAuth"
    assert args[2].strip().startswith("function")


def test_build_absence_context_populates_fields_and_prompt(extractor):
    method = extractor.method_by_full_name(ADMIN_HANDLER)
    hits = extractor.find_control_triggers("javascript")[ADMIN_HANDLER]
    ctx = extractor.build_absence_context(method, "javascript", hits)

    assert ctx.context_id.startswith("absence:")
    assert ctx.control_triggers and ctx.guard_evidence == []
    assert not ctx.data_flow_paths

    text = ctx.to_absence_prompt_text()
    assert "Operations found in this function" in text
    assert "(none)" in text  # empty guard evidence rendered explicitly
    assert "CPG node 101" in text  # the db_read trigger node id
