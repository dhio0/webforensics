"""Scheduling, method routing, and portable restore regression tests."""

from __future__ import annotations

import gzip
import hashlib
import json
from collections import Counter
from itertools import pairwise
from pathlib import Path

import pytest
from lab.v2 import background, collect, crawl_app, pacing, portable, prepare_background
from lab.v2 import restore_webroot as restore
from lab.v2.self_check import timing_checks


def test_schedule_preserves_source_gaps_and_bounds_rolling_bursts() -> None:
    regular = pacing.scaled_schedule([0, 1, 3, 9], rate=4)
    assert regular == pytest.approx([0, 1 / 9, 3 / 9, 1])
    # Real traces include same-second bursts, not equally spaced arrivals.
    stamps = [0.0] * 300 + [1.0] * 300 + [100.0] * 300
    schedule = pacing.scaled_schedule(stamps)
    assert all(schedule[i] - schedule[i - 20] >= 1.009 for i in range(20, len(schedule)))
    assert max(Counter(int(value) for value in schedule).values()) <= 20
    assert 2 <= len(schedule) / schedule[-1] <= 5
    assert len(set(round(b - a, 5) for a, b in pairwise(schedule))) > 1


@pytest.mark.parametrize("stamps", [[1], [1, 1], [2, 1]])
def test_schedule_rejects_missing_or_reversed_source_timing(stamps) -> None:
    with pytest.raises(ValueError):
        pacing.scaled_schedule(stamps)


def test_live_clock_rejects_suspend_instead_of_catching_up(monkeypatch) -> None:
    values = iter([100, 130])
    monkeypatch.setattr(pacing.time, "monotonic", lambda: next(values))
    monkeypatch.setattr(pacing.time, "time", lambda: 100)
    clock = pacing.LiveClock()
    with pytest.raises(RuntimeError, match="discard run"):
        clock.wait_until(1)


def test_hand_actions_are_seeded_and_last_agent_command_has_three_minute_span(
    tmp_path: Path, monkeypatch
) -> None:
    now = [0.0]

    class Clock:
        origin = 0.0

        def wait_until(self, deadline):
            now[0] = deadline

    monkeypatch.setattr(pacing, "LiveClock", Clock)
    monkeypatch.setattr(pacing.time, "monotonic", lambda: now[0])
    pacer = pacing.HandPacer(5001, tmp_path / "hand.json")
    pacer.before("recon")
    pacer.before("login")
    assert 45 <= now[0] <= 60
    pacer.before("agent_command", minimum_span=True)
    assert now[0] >= 185
    assert len(json.loads((tmp_path / "hand.json").read_text())) == 3


def test_crawl_reads_form_methods_including_relative_actions() -> None:
    parser = crawl_app.Links()
    parser.feed('<form method="post" action="../login.php"><form action="/search">')
    assert parser.forms == [("POST", "../login.php"), ("GET", "/search")]


def test_crawl_rejects_static_html_fallback_and_deduplicates_tracking_ids() -> None:
    assert crawl_app.static_html_fallback("/assets/missing.js", "text/html; charset=utf-8")
    assert not crawl_app.static_html_fallback("/assets/real.js", "text/javascript")
    assert not crawl_app.static_html_fallback("/index.php", "text/html")
    assert crawl_app.crawl_query("sid=123&action=search&lang=en") == "action=search&lang=en"
    assert crawl_app.crawl_query("sid=456&action=search&lang=en") == "action=search&lang=en"
    assert crawl_app.crawl_query("q=a%20b&value=%2f") == "q=a%20b&value=%2f"


def test_prepare_routes_write_methods_and_preserves_scanner_and_timing(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    methods = ["POST", "PUT", "PATCH", "GET", "HEAD", "POST"]
    lines = []
    for index, method in enumerate(methods):
        scanner = index == 5
        lines.append(
            f'198.18.0.{index + 1} - - [30/Oct/2026:12:00:{index:02} +0000] '
            f'"{method} /original{index}.css?action=unrelated HTTP/1.1" '
            f'{404 if scanner else 200} 1 '
            f'"-" "{"scanner" if scanner else "Browser"}"\n'
        )
    source.write_text("".join(lines))
    urls = tmp_path / "app_urls.txt"
    urls.write_text("/style.css\n/index.php\n")
    (tmp_path / "app_methods.json").write_text(json.dumps({
        "POST": ["/login.php?action=login"], "PUT": ["/profile"], "PATCH": ["/settings"]
    }))
    output = tmp_path / "background.log.gz"
    report = prepare_background.prepare(
        source, urls, output, tmp_path / "report.json", tmp_path / "classes.tsv", limit=6
    )
    with gzip.open(output, "rt") as stream:
        rows = [background.parse_line(line, "") for line in stream]
    assert [r["target"] for r in rows[:3]] == ["/login.php?action=login", "/profile", "/settings"]
    assert rows[5]["target"] == "/original5.css?action=unrelated"  # scanner stays unchanged
    assert rows[4]["timestamp"] == "30/Oct/2026:12:00:04 +0000"
    assert report["post_target_counts"] == {
        "/login.php?action=login": 1, "/original5.css?action=unrelated": 1
    }


def test_archive_pin_rejects_corrupted_cache(tmp_path: Path) -> None:
    sha = "a" * 64
    (tmp_path / (sha + ".zip")).write_bytes(b"wrong archive")
    with pytest.raises(ValueError, match="SHA-256"):
        portable.archive_bytes({"url": "https://example.invalid/archive", "sha256": sha}, tmp_path)


def manifest_row(name: str, content: bytes) -> str:
    return (
        f"{name.encode().hex()}\tf\t{len(content)}\t644\t33\t1\t1\t2\t3\t0\t"
        + hashlib.sha256(content).hexdigest() + "\n"
    )


def test_restore_requires_no_env_or_app_image_and_preserves_trailing_dot(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "repo"
    scenario = root / "benchmark/v2/s01"
    evidence = scenario / "evidence"
    replay = scenario / "replay"
    evidence.mkdir(parents=True)
    replay.mkdir()
    config = {"version": 2, "app_type": "test", "image": "nonexistent-old-image"}
    (replay / "restore.json").write_text(json.dumps(config))
    public = b"public source bytes"
    secret = b"secret-must-never-be-written"
    sha = hashlib.sha256(secret).hexdigest()
    stub = f"DEFANGED {sha} {len(secret)}\n".encode()
    (replay / "restore-overlay").mkdir()
    (replay / "restore-overlay/config.php").write_bytes(stub)
    (evidence / "manifest.tsv").write_text(
        "#columns=path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256\n"
        + manifest_row("file.php..", public) + manifest_row("config.php", secret)
    )
    (evidence / "defanged.tsv").write_text(
        "path\toriginal_sha256\toriginal_size\trole\treason\n"
        f"config.php\t{sha}\t{len(secret)}\tinstall_file\tsecret omitted\n"
    )
    monkeypatch.setattr(restore, "ROOT", root)
    monkeypatch.setattr(restore, "public_files", lambda app: {
        hashlib.sha256(public).hexdigest(): public
    })
    dest = tmp_path / "outside"
    assert restore.restore("s01", dest) == 2
    with open(restore.io_path(dest / "file.php.."), "rb") as stream:
        assert stream.read() == public
    assert (dest / "config.php").read_bytes() == stub
    with pytest.raises(ValueError, match="empty"):
        restore.restore("s01", dest)
    (replay / "restore-overlay/config.php").write_bytes(b"DEFANGED invalid\n")
    with pytest.raises(ValueError, match="invalid defanged stub"):
        restore.restore("s01", tmp_path / "other")
    config["snapshot_path_map"] = {"file.php..": "../../../../escape"}
    (replay / "restore.json").write_text(json.dumps(config))
    with pytest.raises(ValueError, match="unsafe restore overlay"):
        restore.restore("s01", tmp_path / "traversal")


def test_overlay_defangs_unchanged_install_secrets(tmp_path: Path) -> None:
    webroot = tmp_path / "live"
    webroot.mkdir()
    payload = b"database-password-do-not-export"
    (webroot / "wp-config.php").write_bytes(payload)
    manifest = tmp_path / "manifest.tsv"
    manifest.write_text(
        "#columns=path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256\n"
        + manifest_row("wp-config.php", payload)
    )
    output = tmp_path / "evidence"
    output.mkdir()
    (output / "defanged.tsv").write_text("path\toriginal_sha256\toriginal_size\trole\treason\n")
    collect.export_restore_overlay(webroot, collect.read_manifest(manifest), output, set())
    overlay = tmp_path / "replay/restore-overlay/wp-config.php"
    assert overlay.read_bytes().startswith(b"DEFANGED ")
    assert payload not in overlay.read_bytes()
    assert "secret install configuration" in (output / "defanged.tsv").read_text()


def test_timing_metrics_fail_fast_for_fast_background() -> None:
    rows = [{"timestamp": 1, "client_ip": "bg", "request": "GET / HTTP/1.1"}] * 30
    rows.append({"timestamp": 181, "client_ip": "actor", "request": "GET / HTTP/1.1"})
    with pytest.raises(ValueError, match="average"):
        timing_checks(rows, rows[:-1], {"actor"})


def test_timing_metrics_report_native_attack_bursts_separately() -> None:
    bg = [{"timestamp": i / 3, "client_ip": "bg", "request": "GET / HTTP/1.1"}
          for i in range(1200)]
    actor = [{"timestamp": t, "client_ip": "actor", "request": "POST /login HTTP/1.1"}
             for t in [120, *([200] * 80), 310]]
    metrics = timing_checks(bg + actor, bg, {"actor"})
    assert metrics["maximum_background_requests_per_second"] == 3
    assert metrics["maximum_overall_requests_per_second"] == 83
    assert metrics["attack_span_seconds"] == 190
    assert metrics["background_writes_to_static_assets"] == 0
    with pytest.raises(ValueError, match="20 requests"):
        timing_checks(bg + actor, bg + [bg[0]] * 30, {"actor"})
