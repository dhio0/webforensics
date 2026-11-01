"""Automatic analysis on a Wazuh alert (M6+, D92).

The two alert fixtures are real Wazuh 4.14.9 alerts captured from the integrator (the
file it passes to custom-webforensics), with the container's host name replaced by
`web01`: a realtime FIM `added` (rule 554) and a web attack answered 200 (rule 31106).
"""

import json
import os
import shutil
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from webforensics.adapters.wazuh import trigger
from webforensics.adapters.wazuh.trigger import (
    Plan,
    Site,
    Steps,
    TriggerConfig,
    claim,
    decide,
    handle_alert,
    run,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "wazuh_trigger"
GOLDEN = Path(__file__).parents[1] / "golden"
NOW = datetime(2026, 11, 1, 11, 0, tzinfo=UTC)


def _alert(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _config(tmp_path: Path, **over) -> TriggerConfig:
    values = dict(indexer="https://indexer:9200", user="reader", password_file="x",
                  out_dir=str(tmp_path / "out"), settle_seconds=0,
                  sites={"web01": Site("/var/www/html", ("/var/log/nginx/access.log",))})
    values.update(over)
    return TriggerConfig(**values)


def test_real_fim_alert_inside_the_docroot_triggers(tmp_path):
    decision = decide(_alert("fim_added_alert"), _config(tmp_path))
    plan = decision.plan
    assert plan is not None and plan.reason == "fim" and plan.rule_id == "554"
    assert plan.detail == "/var/www/html/uploads/wf-trigger-test.php"
    assert (plan.agent_name, plan.agent_id, plan.agent_ip) == ("web01", "001", "10.0.0.5")
    when = datetime.fromisoformat(plan.alert_time)
    assert when == datetime(2026, 11, 1, 10, 40, 40, 162000, tzinfo=UTC)
    assert datetime.fromisoformat(plan.since) == when - timedelta(minutes=120)


def test_real_web_attack_alert_on_the_access_log_triggers(tmp_path):
    plan = decide(_alert("web_attack_alert"), _config(tmp_path)).plan
    assert plan is not None and plan.reason == "web_attack" and plan.rule_id == "31106"
    assert "UNION" in plan.detail


@pytest.mark.parametrize(("change", "why"), [
    (lambda a: a["syscheck"].update(path="/etc/passwd"), "outside the docroot"),
    (lambda a: a["syscheck"].update(event="deleted"), "not a write"),
    (lambda a: a["agent"].update(name="db01"), "not configured"),
    (lambda a: a["rule"]["groups"].append("webforensics"), "own write-back"),
    (lambda a: a.update(data={"integration": "webforensics"}), "own write-back"),
])
def test_fim_alerts_that_must_not_trigger(tmp_path, change, why):
    alert = _alert("fim_added_alert")
    change(alert)
    decision = decide(alert, _config(tmp_path))
    assert decision.plan is None and why in decision.why


def test_web_rule_on_another_log_or_another_rule_does_not_trigger(tmp_path):
    alert = _alert("web_attack_alert")
    alert["location"] = "/var/log/other.log"
    assert "not a configured access log" in decide(alert, _config(tmp_path)).why
    alert = _alert("web_attack_alert")
    alert["rule"]["id"] = "31108"
    assert "not a trigger" in decide(alert, _config(tmp_path)).why


def test_claim_honours_the_cool_down(tmp_path):
    state = tmp_path / "state"
    assert claim(state, "web01", NOW, 15)
    assert not claim(state, "web01", NOW + timedelta(minutes=5), 15)
    assert claim(state, "db01", NOW + timedelta(minutes=5), 15)  # per agent
    assert claim(state, "web01", NOW + timedelta(minutes=16), 15)


def test_claim_respects_a_fresh_lock_and_clears_a_stale_one(tmp_path):
    state = tmp_path / "state"
    assert claim(state, "web01", NOW, 15)
    lock = next(state.glob("*.last")).with_suffix(".lock")
    lock.write_text("", encoding="utf-8")
    assert not claim(state, "web01", NOW + timedelta(hours=1), 15)  # another call holds it
    old = time.time() - trigger.STALE_LOCK_SECONDS - 5
    os.utime(lock, (old, old))
    assert claim(state, "web01", NOW + timedelta(hours=1), 15)


def _write_config(tmp_path: Path) -> Path:
    path = tmp_path / "trigger.json"
    path.write_text(json.dumps({
        "indexer": "https://indexer:9200", "user": "reader", "password_file": "x",
        "out_dir": str(tmp_path / "out"), "settle_seconds": 0,
        "sites": {"web01": {"docroot": "/var/www/html/",
                            "access_logs": ["/var/log/nginx/access.log"]}},
    }), encoding="utf-8")
    return path


def test_handle_alert_spawns_one_worker_per_cool_down(tmp_path):
    config, alert_file = _write_config(tmp_path), tmp_path / "a.alert"
    shutil.copy(FIXTURES / "fim_added_alert.json", alert_file)
    spawned = []
    first = handle_alert(alert_file, config, spawn=spawned.append, now=NOW)
    assert first.plan is not None and len(spawned) == 1
    command = spawned[0]
    assert command[1:4] == ["-m", "webforensics.adapters.wazuh.trigger", "run"]
    plan = Plan(**json.loads(Path(command[4]).read_text(encoding="utf-8")))
    assert plan == first.plan
    second = handle_alert(alert_file, config, spawn=spawned.append,
                          now=NOW + timedelta(minutes=1))
    assert second.plan is None and "cool-down" in second.notes[0] and len(spawned) == 1
    log = (tmp_path / "out" / "trigger.log").read_text(encoding="utf-8")
    assert "started fim analysis for web01" in log


def test_config_loads_and_normalises(tmp_path):
    config = TriggerConfig.load(_write_config(tmp_path))
    assert config.sites["web01"].docroot == "/var/www/html"
    assert config.web_rules == trigger.DEFAULT_WEB_RULES and config.cooldown_minutes == 15


def _plan(tmp_path) -> Plan:
    plan = decide(_alert("fim_added_alert"), _config(tmp_path)).plan
    assert plan is not None
    return plan


def test_worker_pulls_analyzes_and_writes_back(tmp_path):
    config, sent, pulled = _config(tmp_path), [], []

    def analyze(cfg, recording, out_dir):
        target = out_dir / "report.json"
        shutil.copy(GOLDEN / "scenario_f.json", target)
        return target

    steps = Steps(pull=lambda cfg, plan, until, out: pulled.append((plan.since, until, out)),
                  analyze=analyze, send=lambda msgs, path: sent.extend(msgs) or len(msgs),
                  sleep=lambda s: None)
    case_dir = run(_plan(tmp_path), config, steps, now=lambda: NOW)
    assert case_dir is not None and pulled[0][1] == NOW
    assert pulled[0][2] == case_dir / "recording.jsonl"
    assert len(sent) == 3
    assert all(m.startswith("1:[001] (web01) 10.0.0.5->webforensics:{") for m in sent)
    events = [json.loads(line) for line in
              (case_dir / "writeback.jsonl").read_text(encoding="utf-8").splitlines()]
    body = events[0]["webforensics"]
    assert body["type"] == "summary" and body["trigger"] == "fim" and body["agent"] == "web01"
    assert len(body["report_sha256"]) == 64


def test_worker_reports_a_failure_back_to_wazuh(tmp_path):
    sent = []

    def broken_pull(cfg, plan, until, out):
        raise ConnectionRefusedError("indexer unreachable")

    steps = Steps(pull=broken_pull, analyze=lambda *a: Path("never"),
                  send=lambda msgs, path: sent.extend(msgs) or len(msgs), sleep=lambda s: None)
    assert run(_plan(tmp_path), _config(tmp_path), steps, now=lambda: NOW) is None
    [text] = sent
    body = json.loads(text.split("->webforensics:", 1)[1])["webforensics"]
    assert body["type"] == "trigger_error" and "indexer unreachable" in body["error"]
    assert "failed web01" in (tmp_path / "out" / "trigger.log").read_text(encoding="utf-8")


def test_main_usage():
    assert trigger.main([]) == 2
