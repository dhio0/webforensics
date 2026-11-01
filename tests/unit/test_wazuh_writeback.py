"""Write-back to Wazuh (M6+, D92): events, queue messages, the CLI and the rules file."""

import json
import re
import socket
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webforensics.adapters.wazuh import queue
from webforensics.adapters.wazuh.queue import Agent, WritebackError, message
from webforensics.adapters.wazuh.writeback import build_events, write_jsonl
from webforensics.cli import app, load_report

ROOT = Path(__file__).parents[2]
GOLDEN = ROOT / "tests" / "golden"
RULES = ROOT / "lab" / "wazuh" / "rules" / "webforensics_rules.xml"
runner = CliRunner()


def _events(name: str):
    return build_events(load_report(GOLDEN / f"scenario_{name}.json"), report_sha256="ab" * 32)


def test_compromise_gives_summary_files_and_attackers():
    events = _events("f")
    assert all(e["integration"] == "webforensics" for e in events)
    body = [e["webforensics"] for e in events]
    assert [b["type"] for b in body] == ["summary", "affected_file", "attacker_ip"]
    summary = body[0]
    assert summary["compromised"] == "yes" and summary["root_cause_found"] == "yes"
    assert summary["affected_files"] == "1" and summary["attackers"] == "1"
    assert summary["root_cause"]["path"] == "/admin/login.php"
    assert summary["root_cause"]["vuln_class"] == "sql_injection_auth_bypass"
    assert summary["root_cause"]["evidence"] == "access.log:5"
    assert body[1]["path"] == "uploads/scenario-f-marker.php" and len(body[1]["sha256"]) == 64
    assert body[2]["ip"] == "172.30.0.1"
    assert {b["report_sha256"] for b in body} == {"ab" * 32}


def test_no_compromise_gives_one_quiet_summary():
    [event] = _events("d")
    summary = event["webforensics"]
    assert summary["compromised"] == "no" and summary["root_cause_found"] == "no"
    assert "root_cause" not in summary and summary["attacker_ips"] == []


def test_events_are_deterministic_and_flat_enough_for_rules():
    assert _events("f") == _events("f")
    for event in _events("f"):
        for key, value in event["webforensics"].items():
            assert isinstance(value, str | list | dict), key


def test_message_for_the_manager_and_for_an_agent():
    event = {"integration": "webforensics", "webforensics": {"type": "attacker_ip"}}
    assert message(event) == ('1:webforensics:{"integration":"webforensics",'
                              '"webforensics":{"type":"attacker_ip"}}')
    assert message(event, Agent("000", "manager")).startswith("1:webforensics:{")
    # Same escaping as Wazuh's integrations: | doubled, : as |:
    text = message(event, Agent("001", "web:01|a", "10.0.0.5"))
    assert text.startswith("1:[001] (web|:01||a) 10.0.0.5->webforensics:{")


def test_message_refuses_what_analysisd_would_cut():
    event = {"integration": "webforensics", "webforensics": {"x": "a" * 70000}}
    with pytest.raises(WritebackError, match="too large"):
        message(event)


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs Unix sockets")
def test_send_delivers_one_datagram_per_event():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "queue"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        server.bind(str(path))
        try:
            assert queue.send(["1:webforensics:{}", "1:webforensics:{\"a\":1}"], path) == 2
            assert server.recv(100) == b"1:webforensics:{}"
            assert server.recv(100) == b'1:webforensics:{"a":1}'
        finally:
            server.close()


def test_send_fails_clearly_without_a_socket(tmp_path):
    with pytest.raises(WritebackError):
        queue.send(["1:webforensics:{}"], tmp_path / "missing")


def test_jsonl_round_trip(tmp_path):
    out = tmp_path / "events.jsonl"
    write_jsonl(_events("f"), out)
    assert [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()] \
        == _events("f")


def test_cli_writes_events(tmp_path):
    out = tmp_path / "events.jsonl"
    result = runner.invoke(app, ["writeback", str(GOLDEN / "scenario_f.json"), "--out", str(out)])
    assert result.exit_code == 0, result.output
    lines = out.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["webforensics"]["type"] == "summary" and len(lines) == 3


@pytest.mark.parametrize("args", [[], ["--out", "x.jsonl", "--agent-id", "001"]])
def test_cli_refuses_incomplete_options(args):
    result = runner.invoke(app, ["writeback", str(GOLDEN / "scenario_f.json"), *args])
    assert result.exit_code == 2


def _rules():
    return ET.parse(RULES).getroot().findall("rule")


def test_rules_use_the_custom_range_and_cover_every_event_type():
    rules = _rules()
    ids = [int(r.get("id")) for r in rules]
    assert len(ids) == len(set(ids)) and all(100800 <= i <= 100809 for i in ids)
    matched = set()
    for rule in rules:
        for f in rule.findall("field"):
            if f.get("name") == "webforensics.type":
                matched.add(f.text.strip("^$"))
    assert matched == {"summary", "affected_file", "attacker_ip", "trigger_error"}


def test_rule_descriptions_name_fields_the_events_have():
    fields = set()
    for event in _events("f"):
        for key, value in event["webforensics"].items():
            fields.add(f"webforensics.{key}")
            if isinstance(value, dict):
                fields |= {f"webforensics.{key}.{k}" for k in value}
    fields |= {"webforensics.agent", "webforensics.error"}  # trigger_error events
    for rule in _rules():
        used = set(re.findall(r"\$\(([\w.]+)\)", rule.find("description").text))
        assert used <= fields, (rule.get("id"), used - fields)
