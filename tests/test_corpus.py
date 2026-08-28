from cpgvd.corpus import read_labels, split_by_app, summarize, write_labels
from cpgvd.models import MutationRecord


def _rec(app, operator="M1", control="authentication", line=1):
    return MutationRecord(
        id=f"{app}::{operator}::f.js::{line}",
        app=app,
        operator=operator,
        control_class=control,
        file="f.js",
        start_line=line,
        end_line=line,
        original_text="x",
    )


def test_write_then_read_labels_roundtrips(tmp_path):
    records = [_rec("a", line=1), _rec("b", operator="M4", control="session", line=9)]
    path = write_labels(records, tmp_path / "sub" / "labels.jsonl")
    back = read_labels(path)
    assert [r.model_dump() for r in back] == [r.model_dump() for r in records]


def test_split_by_app_keeps_each_app_whole():
    records = [_rec(f"app{i}", line=j) for i in range(20) for j in range(5)]
    train, holdout = split_by_app(records, holdout_frac=0.3)

    train_apps = {r.app for r in train}
    holdout_apps = {r.app for r in holdout}
    assert train_apps.isdisjoint(holdout_apps)
    assert train_apps | holdout_apps == {f"app{i}" for i in range(20)}
    # roughly 30% of apps held out (not mutations)
    assert 3 <= len(holdout_apps) <= 9


def test_split_by_app_is_deterministic_and_order_independent():
    records = [_rec(f"app{i}") for i in range(30)]
    a = split_by_app(records)
    b = split_by_app(list(reversed(records)))
    assert {r.app for r in a[1]} == {r.app for r in b[1]}


def test_summarize_counts_by_operator_and_control():
    records = [
        _rec("a", "M1", "authentication"),
        _rec("a", "M4", "session", line=2),
        _rec("b", "M1", "authentication"),
    ]
    s = summarize(records)
    assert s["instances"] == 3
    assert s["apps"] == 2
    assert s["by_operator"] == {"M1": 2, "M4": 1}
    assert s["by_control_class"] == {"authentication": 2, "session": 1}
