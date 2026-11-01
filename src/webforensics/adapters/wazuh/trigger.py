"""Run an analysis automatically when Wazuh raises a webroot or web-attack alert (M6+, D92).

Wazuh's integrator runs `/var/ossec/integrations/custom-webforensics` for each alert
that passes its `<integration>` filters, with the alert file as the first argument
(docs/wazuh-notes.md section 11). That wrapper calls `alert` here, which:
1. decides from the alert alone whether it is worth an analysis (`decide`): a FIM change
   inside a configured agent's docroot, or a web-attack rule on one of its access logs;
   never our own write-back alerts, so the loop cannot feed itself;
2. claims the agent for a cool-down period, so a burst of alerts gives one analysis;
3. starts a detached worker (`run`) and returns at once, because the integrator waits
   for the script.

The worker waits a little for late events, pulls the window from the indexer
(`pull`, read-only user), analyzes the recording offline, writes the report and the
viewer, and sends the conclusions back to Wazuh (`writeback`). A failure is sent back
too, as a `trigger_error` event, so it is visible where the alert was.
"""

import hashlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from webforensics.adapters.wazuh.queue import DEFAULT_SOCKET, INTEGRATION, Agent, message, send

DEFAULT_CONFIG = Path("/var/ossec/etc/webforensics/trigger.json")
# Web rules that mean "an attack pattern was seen" (ruleset/rules/0245-web_rules.xml):
# SQLi 31103, common attack 31104, XSS 31105, attack answered 200 31106, encoded SQLi
# 31164/31165/31170/31171. Frequency rules are left out: they repeat the same requests.
DEFAULT_WEB_RULES = ("31103", "31104", "31105", "31106", "31164", "31165", "31170", "31171")
FIM_EVENTS = ("added", "modified")
STALE_LOCK_SECONDS = 60


@dataclass(frozen=True)
class Site:
    docroot: str
    access_logs: tuple[str, ...]
    error_logs: tuple[str, ...] = ()


@dataclass(frozen=True)
class TriggerConfig:
    indexer: str
    user: str
    password_file: str
    out_dir: str
    sites: dict[str, Site]  # by Wazuh agent name
    ca_cert: str | None = None
    tls_server_name: str | None = None
    lookback_minutes: int = 120
    settle_seconds: int = 30
    cooldown_minutes: int = 15
    web_rules: tuple[str, ...] = DEFAULT_WEB_RULES
    socket: str = str(DEFAULT_SOCKET)
    display_offset: str = "+07:00"

    @classmethod
    def load(cls, path: Path) -> "TriggerConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        sites = {name: Site(docroot=s["docroot"].rstrip("/"),
                            access_logs=tuple(s["access_logs"]),
                            error_logs=tuple(s.get("error_logs", ())))
                 for name, s in data.pop("sites").items()}
        if "web_rules" in data:
            data["web_rules"] = tuple(str(r) for r in data["web_rules"])
        return cls(sites=sites, **data)


@dataclass(frozen=True)
class Plan:
    """One analysis to run, decided from one alert."""

    agent_name: str
    agent_id: str
    agent_ip: str
    reason: str  # "fim" or "web_attack"
    alert_id: str
    rule_id: str
    alert_time: str  # ISO 8601
    since: str
    detail: str = ""  # the changed path or the request line, for the log

    def agent(self) -> Agent:
        return Agent(self.agent_id, self.agent_name, self.agent_ip or "any")


@dataclass
class Decision:
    plan: Plan | None
    why: str = ""
    notes: list[str] = field(default_factory=list)


def _own(alert: dict[str, Any]) -> bool:
    groups = alert.get("rule", {}).get("groups", [])
    data = alert.get("data", {})
    return INTEGRATION in groups or data.get("integration") == INTEGRATION


def alert_time(alert: dict[str, Any]) -> datetime:
    """Wazuh writes `2026-10-29T10:40:56.338+0700`; Python 3.11 parses that form."""
    return datetime.fromisoformat(alert["timestamp"]).astimezone(UTC)


def decide(alert: dict[str, Any], config: TriggerConfig) -> Decision:
    if _own(alert):
        return Decision(None, "own write-back alert")
    agent = alert.get("agent", {})
    name = agent.get("name", "")
    site = config.sites.get(name)
    if site is None:
        return Decision(None, f"agent {name!r} is not configured")
    rule = alert.get("rule", {})
    groups = rule.get("groups", [])
    syscheck = alert.get("syscheck", {})
    if "syscheck" in groups and syscheck:
        path = syscheck.get("path", "")
        if syscheck.get("event") not in FIM_EVENTS:
            return Decision(None, f"FIM event {syscheck.get('event')!r} is not a write")
        if not path.startswith(site.docroot + "/"):
            return Decision(None, f"{path} is outside the docroot {site.docroot}")
        reason, detail = "fim", path
    elif str(rule.get("id")) in config.web_rules:
        location = alert.get("location", "")
        if location not in site.access_logs:
            return Decision(None, f"web rule on {location!r}, not a configured access log")
        reason, detail = "web_attack", alert.get("full_log", "")[:300]
    else:
        return Decision(None, f"rule {rule.get('id')} is not a trigger")
    when = alert_time(alert)
    plan = Plan(agent_name=name, agent_id=str(agent.get("id", "000")),
                agent_ip=agent.get("ip", "any"), reason=reason, alert_id=alert.get("id", ""),
                rule_id=str(rule.get("id", "")), alert_time=when.isoformat(),
                since=(when - timedelta(minutes=config.lookback_minutes)).isoformat(),
                detail=detail)
    return Decision(plan, reason)


def claim(state_dir: Path, agent: str, now: datetime, cooldown_minutes: int) -> bool:
    """True if no analysis for this agent started within the cool-down; records `now`.

    A lock file makes the read-and-write atomic between integrator calls that overlap.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    safe = hashlib.sha256(agent.encode("utf-8")).hexdigest()[:16]
    lock, stamp = state_dir / f"{safe}.lock", state_dir / f"{safe}.last"
    try:  # a lock left by a killed process must not block the agent forever
        if time.time() - lock.stat().st_mtime > STALE_LOCK_SECONDS:
            lock.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    try:
        if stamp.exists():
            last = datetime.fromisoformat(stamp.read_text(encoding="utf-8").strip())
            if now - last < timedelta(minutes=cooldown_minutes):
                return False
        stamp.write_text(now.isoformat(), encoding="utf-8")
        return True
    finally:
        os.close(fd)
        lock.unlink(missing_ok=True)


def _log(config: TriggerConfig, text: str) -> None:
    out = Path(config.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).isoformat(timespec="seconds")
    with (out / "trigger.log").open("a", encoding="utf-8") as fh:
        fh.write(f"{stamp} {text}\n")


def handle_alert(alert_file: Path, config_path: Path,
                 spawn: Callable[[list[str]], None] | None = None,
                 now: datetime | None = None) -> Decision:
    """The integrator's entry point: decide, claim, and start the worker."""
    config = TriggerConfig.load(config_path)
    alert = json.loads(alert_file.read_text(encoding="utf-8"))
    decision = decide(alert, config)
    if decision.plan is None:
        return decision
    plan, now = decision.plan, now or datetime.now(UTC)
    if not claim(Path(config.out_dir) / "state", plan.agent_name, now,
                 config.cooldown_minutes):
        decision.notes.append("cool-down: an analysis for this agent already started")
        decision.plan = None
        return decision
    plans = Path(config.out_dir) / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    plan_file = plans / f"{now:%Y%m%dT%H%M%SZ}-{plan.agent_id}.json"
    plan_file.write_text(json.dumps(asdict(plan), indent=2), encoding="utf-8")
    command = [sys.executable, "-m", "webforensics.adapters.wazuh.trigger", "run",
               str(plan_file), str(config_path)]
    (spawn or _spawn_detached)(command)
    _log(config, f"started {plan.reason} analysis for {plan.agent_name} (alert {plan.alert_id}, "
                 f"rule {plan.rule_id}): {plan.detail}")
    return decision


def _spawn_detached(command: list[str]) -> None:
    subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)


@dataclass(frozen=True)
class Steps:
    """The worker's side effects, replaceable in tests."""

    pull: Callable[[TriggerConfig, Plan, datetime, Path], None]
    analyze: Callable[[TriggerConfig, Path, Path], Path]  # returns report.json
    send: Callable[[list[str], Path], int]
    sleep: Callable[[float], None] = time.sleep


def _pull(config: TriggerConfig, plan: Plan, until: datetime, out: Path) -> None:
    from webforensics.adapters.wazuh.client import Credentials, IndexerClient
    from webforensics.adapters.wazuh.pull import PullRequest, pull

    site = config.sites[plan.agent_name]
    secret = Path(config.password_file).read_text(encoding="utf-8").strip()
    client = IndexerClient(config.indexer, Credentials(config.user, secret),
                           ca_file=config.ca_cert, server_name=config.tls_server_name)
    pull(client, PullRequest(agent=plan.agent_name, since=datetime.fromisoformat(plan.since),
                             until=until, docroot=site.docroot,
                             access_logs=site.access_logs, error_logs=site.error_logs), out)


def _analyze(config: TriggerConfig, recording: Path, out_dir: Path) -> Path:
    from webforensics.analysis import EvidenceInputs, analyze
    from webforensics.correlate import CorrelationConfig
    from webforensics.report import render, render_viewer
    from webforensics.report.text import parse_display_offset

    report = analyze(EvidenceInputs(wazuh_recording=recording), CorrelationConfig(),
                     datetime.now(UTC))
    tz = parse_display_offset(config.display_offset)
    for ext, text in render(report, tz).items():
        (out_dir / f"report.{ext}").write_text(text, encoding="utf-8", newline="\n")
    (out_dir / "viewer.html").write_text(render_viewer(report, tz), encoding="utf-8",
                                         newline="\n")
    return out_dir / "report.json"


REAL_STEPS = Steps(pull=_pull, analyze=_analyze, send=lambda msgs, path: send(msgs, path))


def run(plan: Plan, config: TriggerConfig, steps: Steps = REAL_STEPS,
        now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> Path | None:
    """The worker: pull, analyze, write the report, send the conclusions back."""
    steps.sleep(config.settle_seconds)  # FIM and archive events reach the indexer late
    started = now()
    case_dir = Path(config.out_dir) / "cases" / f"{started:%Y%m%dT%H%M%SZ}-{plan.agent_id}"
    case_dir.mkdir(parents=True, exist_ok=True)
    socket_path = Path(config.socket)
    try:
        recording = case_dir / "recording.jsonl"
        steps.pull(config, plan, started, recording)
        report_json = steps.analyze(config, recording, case_dir)
        from webforensics.adapters.wazuh.writeback import build_events, write_jsonl
        from webforensics.cli import load_report

        digest = hashlib.sha256(report_json.read_bytes()).hexdigest()
        events = build_events(load_report(report_json), report_sha256=digest)
        for event in events:
            event[INTEGRATION]["agent"] = plan.agent_name
            event[INTEGRATION]["trigger"] = plan.reason
            event[INTEGRATION]["case_dir"] = str(case_dir)
        write_jsonl(events, case_dir / "writeback.jsonl")
        steps.send([message(e, plan.agent()) for e in events], socket_path)
        _log(config, f"done {plan.agent_name}: {len(events)} event(s) sent, {case_dir}")
        return case_dir
    except Exception as exc:  # report every failure where the alert was
        error = {"integration": INTEGRATION, INTEGRATION: {
            "type": "trigger_error", "agent": plan.agent_name, "trigger": plan.reason,
            "error": f"{type(exc).__name__}: {exc}"[:500], "case_dir": str(case_dir)}}
        _log(config, f"failed {plan.agent_name}: {error[INTEGRATION]['error']}")
        try:
            steps.send([message(error, plan.agent())], socket_path)
        except Exception as send_exc:  # the queue itself is down; the log has it
            _log(config, f"could not report the failure: {send_exc}")
        return None


def main(argv: list[str]) -> int:
    """`alert <alert file> [config]` from the integration wrapper; `run <plan> <config>`."""
    if len(argv) >= 2 and argv[0] == "alert":
        config = Path(argv[2]) if len(argv) > 2 else Path(
            os.environ.get("WF_TRIGGER_CONFIG", str(DEFAULT_CONFIG)))
        decision = handle_alert(Path(argv[1]), config)
        print(f"webforensics trigger: {decision.why}{'; ' if decision.notes else ''}"
              f"{'; '.join(decision.notes)}")
        return 0
    if len(argv) == 3 and argv[0] == "run":
        plan = Plan(**json.loads(Path(argv[1]).read_text(encoding="utf-8")))
        return 0 if run(plan, TriggerConfig.load(Path(argv[2]))) else 1
    print("usage: trigger alert <alert file> [config] | run <plan file> <config>",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
