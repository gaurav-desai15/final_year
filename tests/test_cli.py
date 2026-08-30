from click.testing import CliRunner

from cpgvd.cli import main


def test_serve_errors_when_web_extra_missing(monkeypatch):
    import importlib.util

    real = importlib.util.find_spec

    monkeypatch.setattr(
        importlib.util, "find_spec",
        lambda name, *a, **k: None if name in ("fastapi", "uvicorn") else real(name, *a, **k),
    )

    result = CliRunner().invoke(main, ["serve"])

    assert result.exit_code != 0
    assert "pip install" in result.output and "web" in result.output


def test_serve_calls_webserver_serve(monkeypatch):
    called = {}
    monkeypatch.setattr("cpgvd.webserver.serve", lambda **kw: called.update(kw))

    result = CliRunner().invoke(main, ["serve", "--host", "0.0.0.0", "--port", "9999", "--no-browser"])

    assert result.exit_code == 0
    assert called == {"host": "0.0.0.0", "port": 9999}
