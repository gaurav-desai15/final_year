"""Tests for the web console's API layer.

The security-relevant tests here are the path-resolution ones. The console is
meant to be runnable on a shared machine, and it takes a filesystem path
straight from the query string -- a dashboard that will open any path the URL
names is a file-disclosure bug, so the allow-list is checked directly rather
than assumed.
"""

from __future__ import annotations

import json

import pytest

from cpgvd.web.server import ArtifactStore, _scan_label

fastapi = pytest.importorskip("fastapi", reason="web console needs the 'web' extra")
from fastapi.testclient import TestClient  # noqa: E402

from cpgvd.web.server import build_app  # noqa: E402


def write_scan(directory, *, findings=1, repo="examples/app"):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.json"
    path.write_text(json.dumps({
        "repo": repo,
        "commit_sha": "0" * 40,
        "languages": ["python"],
        "model": "test-model",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "findings": [
            {
                "id": f"f{i}", "context_id": "c", "file": "app.py",
                "start_line": 10, "end_line": 20, "function": "handler",
                "vulnerability_type": "OS Command Injection", "cwe": "CWE-78",
                "severity": "high", "confidence": "high",
                "title": "Command injection", "description": "d",
            }
            for i in range(findings)
        ],
        "stats": {"duration_seconds": 12.0, "stage_timings": {"joern_parse": 8.0}},
    }), encoding="utf-8")
    return path


def write_run(results_dir, run_id, *, label="", synthetic=False, tp=2, fp=1, fn=1):
    directory = results_dir / run_id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "label": label, "created_at": "2026-01-01T00:00:00Z",
        "datasets": ["d"], "runner": "cpgvd", "synthetic": synthetic, "model": "m",
    }), encoding="utf-8")
    (directory / "run.json").write_text(json.dumps({
        "metadata": {
            "run_id": run_id, "label": label, "created_at": "2026-01-01T00:00:00Z",
            "datasets": ["d"], "runner": "cpgvd", "synthetic": synthetic,
        },
        "cases": [{
            "case_id": "case1", "dataset": "d", "repo": "r", "label": "vulnerable",
            "status": "ok",
            "metrics": {"true_positives": tp, "false_positives": fp,
                        "false_negatives": fn, "true_negatives": 0},
            "matches": [], "false_positives": [], "false_negatives": [],
            "findings_reported": tp + fp, "ground_truth_total": tp + fn,
            "duration_seconds": 30.0, "stage_timings": {"joern_parse": 20.0},
            "peak_memory_mb": 0.0, "llm_calls": 4, "contexts_analyzed": 4,
            "raw_report_path": "",
        }],
    }), encoding="utf-8")
    return directory


@pytest.fixture
def store(tmp_path):
    scans = tmp_path / "scans"
    results = tmp_path / "results"
    results.mkdir()
    write_scan(scans / "run-a")
    return ArtifactStore([scans], results)


class TestPathSafety:
    def test_absolute_path_outside_roots_is_refused(self, store):
        with pytest.raises(PermissionError):
            store.load_scan("/etc/passwd")

    def test_traversal_out_of_a_root_is_refused(self, store):
        escape = store.scan_dirs[0] / ".." / ".." / ".." / "etc" / "passwd"
        with pytest.raises(PermissionError):
            store.load_scan(str(escape))

    def test_symlink_out_of_a_root_is_refused(self, tmp_path, store):
        secret = tmp_path / "secret.json"
        secret.write_text("{}", encoding="utf-8")
        link = store.scan_dirs[0] / "sneaky.json"
        try:
            link.symlink_to(secret)
        except OSError:  # pragma: no cover - filesystems without symlink support
            pytest.skip("symlinks unavailable")
        # resolve() follows the symlink, so the target must be re-checked.
        with pytest.raises(PermissionError):
            store.load_scan(str(link))

    def test_run_id_with_traversal_is_refused(self, store):
        with pytest.raises(PermissionError):
            store.load_run("../../etc")

    def test_path_inside_a_root_is_allowed(self, store):
        report = store.load_scan(str(store.scan_dirs[0] / "run-a" / "report.json"))
        assert report["repo"] == "examples/app"

    def test_missing_file_inside_a_root_is_a_not_found(self, store):
        with pytest.raises(FileNotFoundError):
            store.load_scan(str(store.scan_dirs[0] / "nope" / "report.json"))


class TestArtifactStore:
    def test_lists_scans_with_summary_fields(self, store):
        scans = store.list_scans()
        assert len(scans) == 1
        assert scans[0]["repo"] == "examples/app"
        assert scans[0]["findings"] == 1

    def test_unreadable_scan_is_skipped_not_fatal(self, store):
        bad = store.scan_dirs[0] / "broken"
        bad.mkdir()
        (bad / "report.json").write_text("{not json", encoding="utf-8")
        # One corrupt artifact must not blank the whole listing.
        assert len(store.list_scans()) == 1

    def test_missing_scan_dir_is_tolerated(self, tmp_path):
        results = tmp_path / "r"
        results.mkdir()
        assert ArtifactStore([tmp_path / "absent"], results).list_scans() == []

    def test_lists_runs_newest_first(self, tmp_path):
        results = tmp_path / "results"
        results.mkdir()
        write_run(results, "2026-01-01T00-00-00Z__a", label="a")
        write_run(results, "2026-06-01T00-00-00Z__b", label="b")
        runs = ArtifactStore([tmp_path], results).list_runs()
        assert [r["label"] for r in runs] == ["b", "a"]

    def test_run_without_run_json_is_skipped(self, tmp_path):
        results = tmp_path / "results"
        directory = results / "incomplete"
        directory.mkdir(parents=True)
        (directory / "manifest.json").write_text("{}", encoding="utf-8")
        assert ArtifactStore([tmp_path], results).list_runs() == []

    def test_synthetic_flag_is_surfaced(self, tmp_path):
        # The UI leads with a warning banner off this flag, so it must survive.
        results = tmp_path / "results"
        results.mkdir()
        write_run(results, "r1", label="demo", synthetic=True)
        assert ArtifactStore([tmp_path], results).list_runs()[0]["synthetic"] is True

    def test_scan_label_uses_containing_directory(self, tmp_path):
        root = tmp_path / "out"
        path = root / "scan-1" / "report.json"
        assert _scan_label(path, root) == "scan-1"


class TestApi:
    @pytest.fixture
    def client(self, tmp_path):
        scans = tmp_path / "scans"
        results = tmp_path / "results"
        results.mkdir()
        write_scan(scans / "run-a", findings=2)
        write_run(results, "2026-01-01T00-00-00Z__base", label="base")
        return TestClient(build_app([scans], results))

    def test_health(self, client):
        assert client.get("/api/health").json()["status"] == "ok"

    def test_scans_endpoint(self, client):
        body = client.get("/api/scans").json()
        assert len(body) == 1 and body[0]["findings"] == 2

    def test_scan_endpoint(self, client):
        path = client.get("/api/scans").json()[0]["path"]
        assert len(client.get("/api/scan", params={"path": path}).json()["findings"]) == 2

    def test_scan_outside_roots_returns_403(self, client):
        assert client.get("/api/scan", params={"path": "/etc/passwd"}).status_code == 403

    def test_scan_missing_returns_404(self, client, tmp_path):
        missing = tmp_path / "scans" / "run-a" / "absent.json"
        assert client.get("/api/scan", params={"path": str(missing)}).status_code == 404

    def test_runs_endpoint(self, client):
        assert client.get("/api/runs").json()[0]["label"] == "base"

    def test_run_endpoint(self, client):
        body = client.get("/api/run/2026-01-01T00-00-00Z__base").json()
        assert body["cases"][0]["metrics"]["true_positives"] == 2

    def test_unknown_run_returns_404(self, client):
        assert client.get("/api/run/nope").status_code == 404

    def test_run_traversal_returns_403(self, client):
        assert client.get("/api/run/..%2F..%2Fetc").status_code in (403, 404)

    def test_index_serves_the_console(self, client):
        res = client.get("/")
        assert res.status_code == 200
        assert "cpgvd" in res.text

    def test_static_assets_are_served(self, client):
        for asset in ("/static/app.js", "/static/styles.css"):
            assert client.get(asset).status_code == 200


class TestStaticAssets:
    """The frontend must stay dependency-free and use tokenised colours."""

    def _asset(self, name):
        from cpgvd.web.server import STATIC_DIR

        return (STATIC_DIR / name).read_text(encoding="utf-8")

    def test_no_external_resources(self):
        # The console has to work offline; a CDN reference would break that
        # silently and only on a machine without network.
        for name in ("index.html", "app.js", "styles.css"):
            text = self._asset(name)
            assert "http://" not in text.replace("http://www.w3.org", "")
            assert "https://" not in text.replace("https://www.w3.org", "")

    def test_charts_read_colours_from_css_tokens(self):
        # Hardcoded hex in app.js would let the light and dark palettes drift
        # apart, and would bypass the validated ramps in styles.css.
        import re

        js = self._asset("app.js")
        code = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
        code = re.sub(r"^\s*//.*$", "", code, flags=re.M)
        assert not re.search(r"#[0-9a-fA-F]{6}\b", code), "hardcoded hex colour in app.js"

    def test_green_red_pair_is_absent_from_series_tokens(self):
        # #0ca30c vs #d03b3b measure ΔE 4.1 under deuteranopia; they must never
        # become the TP/FN series colours.
        css = self._asset("styles.css")
        series_block = [ln for ln in css.splitlines() if "--series-" in ln]
        joined = " ".join(series_block).lower()
        assert "#0ca30c" not in joined
        assert "#d03b3b" not in joined
