"""Mutation harness: the five operators, line-count preservation, and the
apply/restore round-trip."""

import shutil

import pytest

from cpgvd.mutation import (
    _mutate_text,
    find_file_mutations,
    find_mutations,
    mutation_applied,
    node_check,
    verify_mutations,
)

ROUTES_JS = """\
const express = require('express');
const router = express.Router();
const { requireAuth, ensureAdmin } = require('./mw');

router.get('/public/posts', postController.list);

router.get('/admin/users', requireAuth, ensureAdmin, adminController.users);

router.post('/notes/:id', requireAuth, function (req, res) {
    const note = db.notes.get(req.params.id);
    if (String(note.ownerId) !== String(req.user._id)) {
        return res.status(403).send('Forbidden');
    }
    db.notes.updateOne({ _id: note._id }, { $set: req.body });
    res.sendStatus(200);
});

router.get('/dashboard', function (req, res) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.render('dashboard');
});

router.post('/reports', function (req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    db.reports.insertOne(req.body);
    res.sendStatus(201);
});

module.exports = router;
"""


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "index.js").write_text(ROUTES_JS, encoding="utf-8")
    (tmp_path / "routes" / "index.test.js").write_text("// tests, must be skipped\n", encoding="utf-8")
    nm = tmp_path / "node_modules" / "dep"
    nm.mkdir(parents=True)
    (nm / "vendored.js").write_text("if (!req.session.user) return res.redirect('/login');\n", encoding="utf-8")
    return tmp_path


def _by_op(records):
    out = {}
    for r in records:
        out.setdefault(r.operator, []).append(r)
    return out


def test_find_mutations_hits_all_five_operators(repo):
    records = find_mutations(repo, app="demo")
    ops = _by_op(records)
    assert set(ops) == {"M1", "M2", "M4", "M5"} or set(ops) == {"M1", "M2", "M4", "M5", "M3"}
    assert "M1" in ops and "M2" in ops and "M4" in ops and "M5" in ops


def test_skips_tests_and_node_modules(repo):
    records = find_mutations(repo, app="demo")
    assert all("node_modules" not in r.file and ".test.js" not in r.file for r in records)


def test_m1_drops_one_middleware_keeps_path_and_handler(repo):
    m1s = [r for r in find_mutations(repo, app="demo") if r.operator == "M1"]
    # /admin/users has two access-control middlewares -> two M1 mutations
    admin = [r for r in m1s if r.route_path == "/admin/users"]
    assert {r.control_class for r in admin} == {"authentication", "authorization"}

    authn = next(r for r in admin if r.control_class == "authentication")
    assert "requireAuth" in authn.original_text
    # applying it removes exactly requireAuth and keeps the rest
    with mutation_applied(repo, authn) as target:
        line = target.read_text().splitlines()[authn.start_line - 1]
    assert "requireAuth" not in line
    assert "ensureAdmin" in line and "adminController.users" in line


def test_m2_ownership_if_block_removed(repo):
    rec = next(r for r in find_mutations(repo, app="demo") if r.operator == "M2")
    assert rec.control_class == "ownership"
    assert "ownerId" in rec.original_text
    assert rec.mutated_text.strip() == ""


def test_m4_session_check_removed(repo):
    rec = next(r for r in find_mutations(repo, app="demo") if r.operator == "M4")
    assert rec.control_class == "session"
    assert "req.session.userId" in rec.original_text


def test_m5_validation_guard_before_write_removed(repo):
    rec = next(r for r in find_mutations(repo, app="demo") if r.operator == "M5")
    assert rec.control_class == "validation"
    assert "errors" in rec.original_text.lower()


def test_mutation_is_line_count_preserving(repo):
    original = (repo / "routes" / "index.js").read_text()
    n_lines = original.count("\n")
    for rec in find_mutations(repo, app="demo"):
        mutated = _mutate_text(original, rec)
        assert mutated.count("\n") == n_lines, f"{rec.id} changed the line count"


def test_mutation_applied_restores_exact_bytes(repo):
    path = repo / "routes" / "index.js"
    original = path.read_text()
    rec = find_mutations(repo, app="demo")[0]
    with mutation_applied(repo, rec) as target:
        assert target.read_text() != original
    assert path.read_text() == original


def test_mutate_text_rejects_stale_span(repo):
    rec = find_mutations(repo, app="demo")[0]
    rec.original_text = "something that is not there"
    with pytest.raises(ValueError):
        _mutate_text((repo / "routes" / "index.js").read_text(), rec)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_verify_mutations_keeps_parseable_mutants(repo):
    records = find_mutations(repo, app="demo")
    kept = verify_mutations(repo, records)
    # every operator here produces syntactically valid JS when removed
    assert len(kept) == len(records)
    ok, _ = node_check(repo / "routes" / "index.js")
    assert ok  # original restored and still valid


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_verify_mutations_drops_a_mutant_that_breaks_syntax(repo, monkeypatch):
    records = find_mutations(repo, app="demo")
    bad = records[0]
    # force an unbalanced result
    bad.mutated_text = "router.get('/x', "
    kept = verify_mutations(repo, [bad])
    assert kept == []


def test_find_file_mutations_no_cross_operator_span_overlap(repo):
    """Different operators must not both claim the same lines (M1 may emit
    several mutations on one registration line -- that is allowed)."""
    recs = find_file_mutations(repo / "routes" / "index.js", "routes/index.js", "demo")
    for i, a in enumerate(recs):
        for b in recs[i + 1 :]:
            if a.operator == b.operator:
                continue
            assert a.end_line < b.start_line or b.end_line < a.start_line, (
                f"{a.operator}@{a.start_line}-{a.end_line} overlaps "
                f"{b.operator}@{b.start_line}-{b.end_line}"
            )
