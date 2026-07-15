import asyncio

import pytest

from cpgvd import cpg_client as cpg_client_module
from cpgvd.cpg_client import CpgClient, CpgQueryError


class FakeCPGQLSClient:
    """Stands in for cpgqls_client.CPGQLSClient so these tests don't need
    a real Joern server."""

    def __init__(self, endpoint, event_loop=None, **kwargs):
        self.endpoint = endpoint
        self.event_loop = event_loop
        self.queries = []
        self.responses = []

    def execute(self, query):
        self.queries.append(query)
        return self.responses.pop(0)


def make_client(monkeypatch, responses):
    fake = None

    def factory(endpoint, event_loop=None, **kwargs):
        nonlocal fake
        fake = FakeCPGQLSClient(endpoint, event_loop=event_loop, **kwargs)
        fake.responses = list(responses)
        return fake

    monkeypatch.setattr(cpg_client_module, "CPGQLSClient", factory)
    client = CpgClient("127.0.0.1", 8080)
    return client, fake


def test_init_passes_an_event_loop_even_with_none_active(monkeypatch):
    """Regression test: on Python 3.12+, asyncio.get_event_loop() raises
    RuntimeError in the main thread when no loop has been set/is running.
    cpgqls-client's own constructor doesn't handle that -- we must create
    and hand it a loop explicitly rather than relying on its internal
    (now-broken) implicit-creation assumption."""
    monkeypatch.setattr(
        cpg_client_module.asyncio,
        "get_event_loop",
        lambda: (_ for _ in ()).throw(RuntimeError("There is no current event loop in thread 'MainThread'.")),
    )
    created_loop = asyncio.new_event_loop()
    monkeypatch.setattr(cpg_client_module.asyncio, "new_event_loop", lambda: created_loop)
    set_calls = []
    monkeypatch.setattr(cpg_client_module.asyncio, "set_event_loop", lambda loop: set_calls.append(loop))

    client, fake = make_client(monkeypatch, responses=[])

    assert fake.event_loop is created_loop
    assert set_calls == [created_loop]
    created_loop.close()


def test_init_reuses_existing_event_loop(monkeypatch):
    existing_loop = asyncio.new_event_loop()
    monkeypatch.setattr(cpg_client_module.asyncio, "get_event_loop", lambda: existing_loop)

    client, fake = make_client(monkeypatch, responses=[])

    assert fake.event_loop is existing_loop
    existing_loop.close()


def test_load_cpg_runs_import_and_escape_helper(monkeypatch):
    monkeypatch.setattr(cpg_client_module.asyncio, "get_event_loop", asyncio.new_event_loop)
    client, fake = make_client(
        monkeypatch,
        responses=[{"success": True, "stdout": "ok"}, {"success": True, "stdout": "ok"}],
    )

    client.load_cpg("/tmp/cpg.bin")

    assert 'importCpg("/tmp/cpg.bin")' in fake.queries[0]
    assert "cpgvdEscape" in fake.queries[1]


def test_run_json_parses_escaped_string_result(monkeypatch):
    monkeypatch.setattr(cpg_client_module.asyncio, "get_event_loop", asyncio.new_event_loop)
    stdout = 'res5: String = "[{\\"name\\":\\"foo\\"}]"'
    client, fake = make_client(monkeypatch, responses=[{"success": True, "stdout": stdout}])

    result = client.run_json("cpg.method.name.l")

    assert result == [{"name": "foo"}]


def test_run_json_raises_on_query_failure(monkeypatch):
    monkeypatch.setattr(cpg_client_module.asyncio, "get_event_loop", asyncio.new_event_loop)
    client, fake = make_client(
        monkeypatch,
        responses=[{"success": False, "stdout": "", "stderr": "boom"}],
    )

    with pytest.raises(CpgQueryError, match="boom"):
        client.run_json("cpg.method.name.l")


def test_run_json_raises_when_no_string_result_found(monkeypatch):
    monkeypatch.setattr(cpg_client_module.asyncio, "get_event_loop", asyncio.new_event_loop)
    client, fake = make_client(monkeypatch, responses=[{"success": True, "stdout": "res5: Int = 42"}])

    with pytest.raises(CpgQueryError, match="could not locate a String result"):
        client.run_json("cpg.method.size")
