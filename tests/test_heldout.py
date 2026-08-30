from pathlib import Path

import pytest

from cpgvd.heldout import _score_label, load_labels, score_heldout
from cpgvd.models import Confidence, Finding, HeldoutLabel, Severity


def _label(challenge="basketAccessChallenge", control="ownership", file="routes/basket.ts", line=15):
    return HeldoutLabel(
        challenge=challenge, name=challenge, category="Broken Access Control",
        control_class=control, file=file, line=line, route_path="/rest/basket/:id",
    )


def _finding(file="routes/basket.ts", start=17, title="Missing ownership check", vtype="IDOR", cwe="CWE-639"):
    return Finding(
        id="f", context_id="c", file=file, start_line=start, end_line=start + 1,
        function="retrieveBasket", vulnerability_type=vtype, cwe=cwe,
        severity=Severity.HIGH, confidence=Confidence.HIGH, title=title,
        description="basket looked up by id with no owner check",
    )


def test_score_label_hit_within_window_and_class():
    res = _score_label(_label(line=15), [_finding(start=18)], window=20)
    assert res.detected and res.matched_control_ok
    assert res.matched_line == 18


def test_score_label_miss_when_far_or_other_file():
    assert not _score_label(_label(line=15), [_finding(start=200)], window=20).detected
    assert not _score_label(_label(line=15), [_finding(file="server.ts", start=15)], window=20).detected


def test_score_label_detected_but_class_mismatch():
    f = _finding(vtype="Missing Authentication", cwe="CWE-306", title="route not authenticated")
    res = _score_label(_label(control="ownership", line=15), [f], window=20)
    assert res.detected and not res.matched_control_ok


def test_score_label_prefers_class_matching_finding():
    wrong = _finding(start=16, vtype="Missing Authentication", cwe="CWE-306", title="no auth")
    right = _finding(start=20, vtype="IDOR", cwe="CWE-639", title="idor")
    res = _score_label(_label(control="ownership", line=15), [wrong, right], window=20)
    assert res.detected and res.matched_control_ok and res.matched_line == 20


def test_load_labels_reads_shipped_juice_shop_file():
    app, commit, labels = load_labels(Path("corpus/heldout/juice-shop.yaml"))
    assert app == "juice-shop"
    assert commit and len(commit) == 40
    assert len(labels) >= 6
    keys = {l.challenge for l in labels}
    assert "changeProductChallenge" in keys and "basketAccessChallenge" in keys
    for l in labels:
        assert l.control_class in {"authentication", "authorization", "ownership", "session", "validation"}
        assert l.line > 0 and l.file


def test_score_heldout_end_to_end(monkeypatch):
    labels = [
        _label("changeProductChallenge", "authorization", "server.ts", 361),
        _label("basketAccessChallenge", "ownership", "routes/basket.ts", 15),
        _label("forgedReviewChallenge", "ownership", "routes/createProductReviews.ts", 14),
    ]
    findings = [
        _finding(file="server.ts", start=364, vtype="Missing Authorization", cwe="CWE-862", title="no authz on PUT"),
        _finding(file="routes/basket.ts", start=17, vtype="IDOR", cwe="CWE-639", title="idor"),
        _finding(file="routes/other.ts", start=99, title="unrelated"),
    ]

    monkeypatch.setattr("cpgvd.heldout.joern_session", _fake_session)
    monkeypatch.setattr("cpgvd.heldout._analyze", lambda *a, **k: (findings, []))
    monkeypatch.setattr("cpgvd.heldout.RuleSets", _FakeRuleSets)

    from cpgvd.config import Config

    rep = score_heldout(Path("."), labels, Config(), app="juice-shop", match_window=20)
    assert rep.n_labels == 3
    assert rep.n_detected == 2  # changeProduct + basketAccess; forgedReview missed
    assert rep.recall == round(2 / 3, 3)
    assert rep.n_findings_total == 3
    assert rep.n_findings_unmatched == 1  # routes/other.ts:99
    assert rep.by_control_class["ownership"]["tp"] == 1
    assert rep.by_control_class["authorization"]["tp"] == 1


class _FakeRuleSets:
    @staticmethod
    def load(_mode):
        return object()


class _fake_session:
    def __init__(self, _config):
        pass

    def __enter__(self):
        return object()

    def __exit__(self, *a):
        return False
