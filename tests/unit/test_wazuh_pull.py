"""`pull`, the indexer client's paging, and the CLI around recordings. No network: the
client's single HTTP method is replaced by a fake indexer (the live check is the lab)."""

from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from tests.unit.test_wazuh_adapter import upload_story
from tests.wazuh_helpers import ACCESS, DOCROOT, recording
from webforensics.adapters.wazuh import schema_v4 as schema
from webforensics.adapters.wazuh.client import Credentials, IndexerClient, IndexerError
from webforensics.adapters.wazuh.pull import PullError, PullRequest, pull
from webforensics.adapters.wazuh.recording import read_recording
from webforensics.cli import app

START = datetime(2026, 10, 27, tzinfo=UTC)


class FakeIndexer(IndexerClient):
    """Answers like OpenSearch: PIT open/close, sorted pages, 404 for missing patterns."""

    def __init__(self, data: dict[str, list[dict[str, object]]]) -> None:
        super().__init__("https://indexer.test:9200", Credentials("reader", "secret"))
        self.data = data
        self.calls: list[tuple[str, str, dict | None]] = []
        self.open_pits: dict[str, str] = {}

    def request(self, method, path, body=None, params=None):
        self.calls.append((method, path, body))
        pattern = path.strip("/").split("/")[0]
        if method == "DELETE" and path == "/_search/point_in_time":
            for pit in body["pit_id"]:
                del self.open_pits[pit]
            return {}
        if method == "POST" and path.endswith("/_search/point_in_time"):
            pit = f"pit{len(self.open_pits)}"
            self.open_pits[pit] = pattern
            return {"pit_id": pit}
        if path == "/_search":
            hits = self.data[self.open_pits[body["pit"]["id"]]]
            start = 0
            if "search_after" in body:
                start = next(i for i, h in enumerate(hits) if h["sort"] == body["search_after"])
                start += 1
            return {"hits": {"hits": hits[start:start + body["size"]]}}
        if pattern not in self.data:
            raise IndexerError(404, "index_not_found_exception")
        return {"hits": {"hits": []}}


def _sorted(hits: list[dict[str, object]]) -> list[dict[str, object]]:
    return [{**h, "sort": [i, h["_id"]]} for i, h in enumerate(hits)]


def _request(**kwargs) -> PullRequest:
    return PullRequest(agent="wf-lab-agent", since=START, until=START + timedelta(days=2),
                       docroot=DOCROOT, access_logs=(ACCESS,), **kwargs)


def test_iter_hits_pages_with_search_after_and_closes_the_pit():
    web, _ = upload_story()
    client = FakeIndexer({schema.ARCHIVES: _sorted(web)})
    got = list(client.iter_hits(schema.ARCHIVES, {"match_all": {}}, schema.SORT, page_size=2))
    assert [h["_id"] for h in got] == ["web1", "web2", "web3"]
    pages = [body for _, path, body in client.calls if path == "/_search"]
    assert [p.get("search_after") for p in pages] == [None, [1, "web2"]]
    assert all(p["sort"] == list(schema.SORT) for p in pages)
    assert client.open_pits == {}


def test_the_pit_is_closed_even_if_the_caller_stops_early():
    client = FakeIndexer({schema.ARCHIVES: _sorted(upload_story()[0])})
    hits = client.iter_hits(schema.ARCHIVES, {}, schema.SORT, page_size=1)
    next(hits)
    hits.close()
    assert client.open_pits == {}


def test_pull_writes_web_and_fim_hits_bounded_by_agent_and_time(tmp_path):
    web, fim = upload_story()
    client = FakeIndexer({schema.ARCHIVES: _sorted(web), schema.ALERTS: _sorted(fim)})
    header = pull(client, _request(), tmp_path / "rec.jsonl", now=START + timedelta(days=3))
    assert header.archives and header.counts == {"web": 3, "fim": 1}
    _, hits = read_recording(tmp_path / "rec.jsonl")
    assert [(h.stream.value, h.doc_id) for h in hits] == [
        ("web", "web1"), ("web", "web2"), ("web", "web3"), ("fim", "fim1")]
    queries = [body["query"] for _, path, body in client.calls if path == "/_search"]
    for query in queries:
        filters = query["bool"]["filter"]
        assert {"term": {"agent.name": "wf-lab-agent"}} in filters
        assert any("range" in f for f in filters)


def test_without_archives_web_events_come_from_alerts(tmp_path):
    web, fim = upload_story()
    client = FakeIndexer({schema.ALERTS: _sorted(web[1:2] + fim)})
    header = pull(client, _request(), tmp_path / "rec.jsonl")
    assert not header.archives and header.web_index == schema.ALERTS


def test_an_indexer_without_4x_alerts_stops_with_a_clear_error(tmp_path):
    with pytest.raises(PullError, match=r"Wazuh 5.x"):
        pull(FakeIndexer({}), _request(), tmp_path / "rec.jsonl")
    assert not (tmp_path / "rec.jsonl").exists()


def test_the_client_refuses_plain_http():
    with pytest.raises(ValueError, match="https"):
        IndexerClient("http://indexer:9200", Credentials("u", "p"))


def test_indexer_errors_do_not_leak_credentials():
    error = IndexerError(401, "Unauthorized")
    assert "secret" not in str(error) and "401" in str(error)


# --- CLI -------------------------------------------------------------------------------

runner = CliRunner()


def test_analyze_reads_a_recording_offline(tmp_path):
    path = recording(tmp_path / "rec.jsonl", *upload_story())
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", "--wazuh-recording", str(path), "--out", str(out),
                                 "--generated-at", "2026-10-30T00:00:00+00:00"])
    assert result.exit_code == 0, result.output
    assert "Root cause" in result.output and "POST /admin/upload.php" in result.output
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "rec.jsonl:3" in md  # the POST, cited by recording line
    assert "Riwayat Wazuh FIM" in md and "file berubah menurut Wazuh FIM" in md


def test_analyze_is_deterministic_on_a_recording(tmp_path):
    path = recording(tmp_path / "rec.jsonl", *upload_story())
    outputs = []
    for run in ("one", "two"):
        out = tmp_path / run
        runner.invoke(app, ["analyze", "--wazuh-recording", str(path), "--out", str(out),
                            "--generated-at", "2026-10-30T00:00:00+00:00"])
        outputs.append([(out / f"report.{ext}").read_bytes() for ext in ("md", "html", "json")])
    assert outputs[0] == outputs[1]


def test_a_recording_cannot_be_mixed_with_file_evidence(tmp_path):
    path = recording(tmp_path / "rec.jsonl", *upload_story())
    log = tmp_path / "access.log"
    log.write_text("", encoding="utf-8")
    result = runner.invoke(app, ["analyze", "--wazuh-recording", str(path), "--log", str(log),
                                 "--out", str(tmp_path / "out")])
    assert result.exit_code == 2 and "used alone" in result.output


def test_analyze_needs_some_evidence(tmp_path):
    result = runner.invoke(app, ["analyze", "--out", str(tmp_path / "out")])
    assert result.exit_code == 2


def test_pull_needs_credentials_and_never_takes_a_password_option(tmp_path, monkeypatch):
    monkeypatch.delenv("WF_WAZUH_USER", raising=False)
    monkeypatch.delenv("WF_WAZUH_PASSWORD", raising=False)
    args = ["pull", "--indexer", "https://127.0.0.1:9200", "--agent", "a",
            "--since", "2026-10-27T00:00:00+00:00", "--docroot", DOCROOT,
            "--access-log", ACCESS, "--out", str(tmp_path / "rec.jsonl")]
    result = runner.invoke(app, args)
    assert result.exit_code == 2 and "credentials missing" in result.output
    assert runner.invoke(app, [*args, "--password", "x"]).exit_code == 2  # no such option


def test_pull_rejects_a_window_without_offset(tmp_path, monkeypatch):
    monkeypatch.setenv("WF_WAZUH_USER", "reader")
    monkeypatch.setenv("WF_WAZUH_PASSWORD", "secret")
    result = runner.invoke(app, ["pull", "--indexer", "https://127.0.0.1:9200", "--agent", "a",
                                 "--since", "2026-10-27T00:00:00", "--docroot", DOCROOT,
                                 "--access-log", ACCESS, "--out", str(tmp_path / "r.jsonl")])
    assert result.exit_code == 2 and "UTC offset" in result.output
