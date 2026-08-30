import json
import time

import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")
from fastapi.testclient import TestClient  # noqa: E402

from cpgvd import webserver  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(webserver, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(webserver, "OUTPUT_DIR", tmp_path / "cpgvd_output")
    monkeypatch.setattr(webserver, "WEB_OUTPUT", tmp_path / "cpgvd_output" / "web")
    monkeypatch.setattr(webserver, "EVAL_DIR", tmp_path / "corpus" / "eval")
    monkeypatch.setattr(webserver, "_ALLOWED_REPORT_ROOTS", ((tmp_path / "cpgvd_output").resolve(),))
    webserver._JOBS.clear()
    return TestClient(webserver.create_app())


def test_health_shape(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert set(r.json()) == {"joern", "ollama"}


def test_benchmark_empty_when_no_eval_dir(client):
    r = client.get("/api/benchmark")
    assert r.status_code == 200
    assert r.json()["has_data"] is False


def test_benchmark_aggregates_eval_json(client, tmp_path):
    ev = tmp_path / "corpus" / "eval"
    ev.mkdir(parents=True)
    (ev / "_aggregate.json").write_text(json.dumps({
        "apps": 13, "mutations": 39, "precision": 0.04, "recall": 0.18,
        "recall_raw": 0.39, "f1": 0.06, "baseline_fp_total": 47,
        "by_operator": {"M1": {"recall": 0.38}}, "per_app": {"foo": {"recall": 0.5}},
    }))
    (ev / "_aggregate-raw.json").write_text(json.dumps({
        "apps": 13, "mutations": 39, "precision": 0.07, "recall": 0.26,
        "recall_raw": 0.26, "f1": 0.11, "baseline_fp_total": 34,
        "by_operator": {"M1": {"recall": 0.44}},
    }))
    (ev / "heldout-juice-shop.json").write_text(json.dumps({
        "grounding": "cpg", "n_labels": 8, "n_detected": 2, "recall": 0.25,
        "class_ok_rate": 0.5, "n_findings_unmatched": 3,
        "by_control_class": {"authorization": {"recall": 0.33}},
    }))
    (ev / "RESULTS.md").write_text("# hi")

    d = client.get("/api/benchmark").json()
    assert d["has_data"] is True
    assert {r["detector"] for r in d["overall"]} == {"cpgvd (grounded)", "cpgvd (ungrounded)"}
    assert d["by_operator"][0]["operator"] == "M1"
    assert d["by_operator"][0]["grounded"] == 0.38
    assert d["heldout"][0]["recall"] == 0.25
    assert d["per_app"][0]["app"] == "foo"
    assert d["results_md"] == "# hi"


def test_report_path_traversal_blocked(client, tmp_path):
    (tmp_path / "secret.json").write_text("{}")
    r = client.get("/api/report", params={"path": "../secret.json"})
    assert r.status_code == 403


def test_reports_listing_and_read(client, tmp_path):
    out = tmp_path / "cpgvd_output"
    out.mkdir()
    (out / "report.json").write_text(json.dumps({"repo": "x/y", "findings": [{"severity": "high"}]}))
    listing = client.get("/api/reports").json()
    assert listing[0]["repo"] == "x/y" and listing[0]["n_findings"] == 1
    got = client.get("/api/report", params={"path": listing[0]["path"]}).json()
    assert got["repo"] == "x/y"


def test_scan_lifecycle_with_fake_runner(client, monkeypatch):
    def fake_run(job):
        job.append("cloning…")
        job.append("done")
        (job.out_dir / "report.json").write_text(json.dumps({"repo": job.request.repo, "findings": []}))
        job.returncode = 0
        job.status = "done"

    monkeypatch.setattr(webserver, "_run_scan", lambda job: fake_run(job))

    started = client.post("/api/scan", json={"repo": "./examples/x", "mode": "absence"})
    assert started.status_code == 200
    jid = started.json()["job_id"]

    snap = {}
    for _ in range(100):
        snap = client.get(f"/api/scan/{jid}").json()
        if snap["status"] != "running":
            break
        time.sleep(0.02)
    assert snap["status"] == "done" and snap["report_available"] is True
    assert "cloning" in snap["log"]

    rep = client.get(f"/api/scan/{jid}/report").json()
    assert rep["repo"] == "./examples/x"


def test_scan_requires_repo(client):
    assert client.post("/api/scan", json={"repo": "   "}).status_code == 400
