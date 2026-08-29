import json
from unittest.mock import patch

from cpgvd.baselines import run_semgrep


def _semgrep_json(results):
    return json.dumps({"results": results})


def test_run_semgrep_parses_results_into_findings(tmp_path):
    (tmp_path / "routes").mkdir()
    payload = _semgrep_json(
        [
            {
                "path": str(tmp_path / "routes" / "index.js"),
                "start": {"line": 12},
                "end": {"line": 12},
                "extra": {"message": "unprotected route", "metadata": {"cwe": "CWE-862"}},
            }
        ]
    )

    class _Proc:
        stdout = payload
        stderr = ""

    with patch("cpgvd.baselines.subprocess.run", return_value=_Proc()):
        findings = run_semgrep(tmp_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.file == "routes/index.js"
    assert f.start_line == 12
    assert f.vulnerability_type == "Missing Access Control"
    assert f.model.startswith("semgrep/")
    assert "pattern match only" in f.context_reasoning


def test_run_semgrep_survives_no_output(tmp_path):
    class _Proc:
        stdout = ""
        stderr = "boom"

    with patch("cpgvd.baselines.subprocess.run", return_value=_Proc()):
        assert run_semgrep(tmp_path) == []
