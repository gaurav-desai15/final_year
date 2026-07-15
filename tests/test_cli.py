from unittest.mock import MagicMock

from click.testing import CliRunner

from cpgvd.cli import main


def test_dashboard_errors_when_streamlit_not_installed(monkeypatch):
    monkeypatch.setattr("cpgvd.cli.shutil.which", lambda name: None)
    runner = CliRunner()

    result = runner.invoke(main, ["dashboard"])

    assert result.exit_code != 0
    assert "streamlit" in result.output.lower()
    assert "pip install" in result.output


def test_dashboard_launches_streamlit_with_report_path(monkeypatch, tmp_path):
    monkeypatch.setattr("cpgvd.cli.shutil.which", lambda name: "/usr/bin/streamlit")
    fake_run = MagicMock()
    monkeypatch.setattr("cpgvd.cli.subprocess.run", fake_run)

    report_path = tmp_path / "report.json"
    runner = CliRunner()

    result = runner.invoke(main, ["dashboard", "--report", str(report_path)])

    assert result.exit_code == 0
    fake_run.assert_called_once()
    cmd = fake_run.call_args.args[0]
    assert "streamlit" in cmd
    assert "run" in cmd
    assert str(report_path) in cmd
    assert cmd[-2] == "--report"
