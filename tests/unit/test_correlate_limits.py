"""Tests for the M3 limitation fixes: proxies, login outcomes, weak seeds, local gaps,
error-log corroboration."""

from tests.correlate_helpers import (
    ATTACKER,
    VISITOR,
    file_ev,
    files,
    line_of,
    numbered,
    request,
    root_event,
)
from webforensics.correlate import CorrelationConfig, correlate
from webforensics.correlate.actors import (
    LoginOutcome,
    login_outcomes,
    parse_networks,
    resolve_actor,
)
from webforensics.correlate.config import CorrelationConfig as Config
from webforensics.correlate.gaps import silence_gaps
from webforensics.models import Confidence, LogCollection
from webforensics.parsers.error_log import ErrorLogFormat, parse_error_line

PROXY = "10.0.0.1"
BYPASS = "/admin/login.php?u=a%27+OR+%271%27%3D%271+--+"
SHELL = "uploads/x.php"


def _outcomes(logs: LogCollection):
    return login_outcomes(list(logs.events), {e.evidence_id: e.client_ip for e in logs.events})


# --- actors behind a reverse proxy ---------------------------------------------------


def test_xff_used_only_from_trusted_proxy_and_rightmost_untrusted_hop():
    proxies = parse_networks(["10.0.0.0/8"])
    spoofed = request(1, 0, "/", ip=PROXY, xff=f"1.1.1.1, {ATTACKER}")
    assert resolve_actor(spoofed, proxies) == ATTACKER
    chained = request(1, 0, "/", ip=PROXY, xff=f"{ATTACKER}, 10.0.0.9")
    assert resolve_actor(chained, proxies) == ATTACKER
    untrusted = request(1, 0, "/", ip=VISITOR, xff=ATTACKER)
    assert resolve_actor(untrusted, proxies) == VISITOR
    garbage = request(1, 0, "/", ip=PROXY, xff="unknown, not-an-ip")
    assert resolve_actor(garbage, proxies) == PROXY
    assert resolve_actor(spoofed, ()) == PROXY


def test_two_clients_behind_one_proxy_are_kept_apart():
    logs = numbered(
        (0, BYPASS, {"ip": PROXY, "xff": VISITOR}),
        (10, "/admin/upload.php", {"method": "POST", "ip": PROXY, "xff": ATTACKER}),
        (12, "/uploads/x.php", {"ip": PROXY, "xff": ATTACKER}),
    )
    evidence = files(file_ev(SHELL, btime=10, ctime=10, mtime=10))
    merged = correlate(logs, evidence)
    assert root_event(merged).description.key == "timeline.auth_bypass_sqli"
    split = correlate(logs, evidence, config=CorrelationConfig(trusted_proxies=("10.0.0.0/8",)))
    root = root_event(split)
    assert line_of(split, root) == 2 and root.actor == ATTACKER
    assert split.iocs.ips == (ATTACKER,)


def test_user_agent_switch_lowers_entry_point_confidence():
    logs = numbered(
        (0, BYPASS, {"ua": "tool-a"}),
        (10, "/admin/upload.php", {"method": "POST", "ua": "tool-b"}),
        (12, "/uploads/x.php", {"ua": "tool-b"}),
    )
    result = correlate(logs, files(file_ev(SHELL, btime=10, ctime=10, mtime=10)))
    assert "actor.user_agent_changed" in [r.key for r in result.root_cause.reasons]
    assert result.root_cause.confidence is Confidence.LOW


# --- login outcomes -------------------------------------------------------------------


def test_login_retried_without_using_area_is_a_failure():
    logs = numbered(
        (0, "/admin/login.php", {"method": "POST", "size": 500}),
        (2, "/admin/style.css"),  # static assets don't prove a session
        (4, "/admin/login.php", {"method": "POST", "size": 500}),
        (6, "/admin/login.php", {"method": "POST", "status": 302, "size": 0}),
        (8, "/admin/dashboard.php"),
    )
    outcome = {e.line_no: _outcomes(logs)[e.evidence_id][0]
               for e in logs.events if e.evidence_id in _outcomes(logs)}
    assert outcome == {1: LoginOutcome.FAILED, 3: LoginOutcome.FAILED,
                       4: LoginOutcome.SUCCEEDED}


def test_login_with_same_response_as_known_failure_is_a_failure():
    logs = numbered(
        (0, "/login.php", {"method": "POST", "size": 812, "ip": VISITOR}),
        (2, "/login.php", {"method": "POST", "size": 812, "ip": VISITOR}),
        (10, "/login.php", {"method": "POST", "size": 812}),
    )
    outcomes = _outcomes(logs)
    last = logs.events[2]
    assert outcomes[last.evidence_id][0] is LoginOutcome.FAILED
    assert outcomes[last.evidence_id][1].key == "login.same_response_as_failure"


def test_failed_200_logins_do_not_become_the_root_cause():
    logs = numbered(
        (0, "/admin/login.php", {"method": "POST", "size": 500}),
        (3, "/admin/login.php", {"method": "POST", "size": 500}),
        (10, "/admin/upload.php", {"method": "POST"}),
        (12, "/uploads/x.php"),
    )
    result = correlate(logs, files(file_ev(SHELL, btime=10, ctime=10, mtime=10)))
    assert root_event(result).description.key == "timeline.upload_exploit"
    failed = [e for e in result.timeline if e.description.key == "timeline.login_failed"]
    assert [line_of(result, e) for e in failed] == [1, 2]


# --- weak seeds: lonely writes and rare POST targets --------------------------------


def _deploy(*extra):
    batch = [file_ev(f"app/f{i}.php", btime=i * 0.5, ctime=i * 0.5, mtime=i * 0.5,
                     content=str(i)) for i in range(6)]
    return files(*batch, *extra)


def test_lonely_php_outside_upload_dir_is_traced_when_a_request_wrote_it():
    logs = numbered((499, "/contact.php", {"method": "POST"}), (510, "/lib/cache.php"))
    result = correlate(logs, _deploy(file_ev("lib/cache.php", btime=500, ctime=500,
                                             mtime=500)))
    assert [f.path for f in result.affected_files] == ["lib/cache.php"]
    created = next(e for e in result.timeline if e.description.key == "timeline.file_created")
    keys = [r.key for r in created.confidence_reasons]
    assert "seed.lonely_write" in keys
    # The only link is a form POST nearby, not an upload: a lead, low (D100).
    assert "accusation.weak" in keys
    assert created.confidence is Confidence.LOW
    assert line_of(result, root_event(result)) == 1


def test_lonely_write_without_http_link_is_listed_for_review_not_accused():
    logs = numbered((0, "/"), (900, "/"))
    result = correlate(logs, _deploy(file_ev("lib/edit.php", btime=500, ctime=500,
                                             mtime=500)))
    assert result.affected_files == ()
    assert result.unexplained_changes == ("lib/edit.php",)
    assert result.timeline == ()


def test_deployed_files_are_not_lonely():
    logs = numbered((0, "/app/f1.php", {"method": "POST"}))
    result = correlate(logs, _deploy())
    assert result.affected_files == () and result.unexplained_changes == ()


def test_rare_post_target_joins_incident_without_a_creation_request():
    logs = numbered(
        (0, "/"),
        (600, "/lib/x.php", {"method": "POST"}),
        (700, "/lib/x.php", {"method": "POST"}),
    )
    result = correlate(logs, _deploy(file_ev("lib/x.php", btime=300, ctime=300, mtime=300)))
    assert [f.path for f in result.affected_files] == ["lib/x.php"]
    assert any(f.rule_id == "CORR-RARE-POST-TARGET" for f in result.findings)
    assert result.root_cause is None
    assert ATTACKER in result.iocs.ips


# --- local silence threshold ----------------------------------------------------------


def test_quiet_night_is_not_a_gap_but_hole_in_busy_traffic_is():
    night = LogCollection(events=tuple(
        request(i + 1, i * 1200 + (4000 if i > 15 else 0), "/") for i in range(30)))
    assert silence_gaps(list(night.events), Config()) == []
    busy = LogCollection(events=tuple(
        request(i + 1, i * 2 + (3600 if i > 15 else 0), "/") for i in range(30)))
    assert len(silence_gaps(list(busy.events), Config())) == 1


# --- error logs ------------------------------------------------------------------------

NGINX_ERR = (
    '2026/10/27 17:00:10 [error] 31#31: *7 FastCGI sent in stderr: "PHP message: PHP Warning:'
    '  demo" while reading response header from upstream, client: 203.0.113.7, server: _, '
    'request: "POST /admin/upload.php HTTP/1.1", upstream: "fastcgi://127.0.0.1:9000", '
    'host: "lab"'
)


def _errors(*lines: str) -> LogCollection:
    parsed = [parse_error_line(line, "error.log", n, ErrorLogFormat.NGINX, "+0700")
              for n, line in enumerate(lines, start=1)]
    return LogCollection(errors=tuple(parsed))


def test_error_log_line_corroborates_the_write_request():
    logs = numbered((10, "/admin/upload.php", {"method": "POST"}), (12, "/uploads/x.php"))
    result = correlate(logs.merged(_errors(NGINX_ERR)),
                       files(file_ev(SHELL, btime=10, ctime=10, mtime=10)))
    root = root_event(result)
    assert [c.source for c in root.citations] == ["access.log", "uploads/x.php", "error.log"]
    assert "error_log.corroborates" in [r.key for r in root.confidence_reasons]


def test_error_log_fills_in_a_missing_access_line_with_low_confidence():
    logs = numbered((0, "/"), (12, "/uploads/x.php"))
    result = correlate(logs.merged(_errors(NGINX_ERR)),
                       files(file_ev(SHELL, btime=10, ctime=10, mtime=10)))
    root = root_event(result)
    assert root.citations[0].source == "error.log"
    assert "creation.error_log_only" in [r.key for r in root.confidence_reasons]
    assert result.root_cause.confidence is Confidence.LOW
