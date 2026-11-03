"""The analysis on damaged copies of the benchmark evidence, through the real parsers (D96).

For every seeded copy: no exception, the same bytes twice, every cited access-log line is
the physical line it names, and every non-blank line is either an event or counted as
unreadable. On undamaged logs: shuffling the lines or adding plain visits from new
addresses does not change who is accused, which files are affected, or which scripts are
reported.
"""

import json
import random
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.correlate_helpers import SCENARIOS
from tests.messy import cut_gzip, damage_log, damage_manifest
from webforensics.analysis import EvidenceInputs, analyze
from webforensics.evaluate import scenario_inputs
from webforensics.parsers.manifest import parse_manifest
from webforensics.report import render
from webforensics.report.text import parse_display_offset

WHEN = datetime(2026, 11, 3, tzinfo=UTC)
OFFSET = parse_display_offset("+07:00")
NAMES = sorted(p.parent.name for p in SCENARIOS.glob("*/ground_truth.json"))


def _case(name: str):
    folder = SCENARIOS / name
    truth = json.loads((folder / "ground_truth.json").read_text(encoding="utf-8"))
    inputs, config = scenario_inputs(folder, truth)
    return inputs, config


def _run(tmp: Path, name: str, log: bytes, *, manifest: bytes | None = None,
         gz: bool = False):
    inputs, config = _case(name)
    log_path = tmp / ("access.log.gz" if gz else "access.log")
    log_path.write_bytes(log)
    man = tmp / "manifest.tsv"
    man.write_bytes(manifest if manifest is not None else inputs.manifest.read_bytes())
    base = None
    if inputs.baseline is not None:
        base = tmp / "baseline.tsv"
        base.write_bytes(inputs.baseline.read_bytes())
    copied = EvidenceInputs(logs=(log_path,), log_format=inputs.log_format, manifest=man,
                            baseline=base, webroot=inputs.webroot, base_dir=tmp)
    return analyze(copied, config, WHEN)


def _conclusions(report):
    r = report.result
    return (set(r.iocs.ips), {f.path for f in r.affected_files}, set(r.log_only_files))


def _original(name: str) -> bytes:
    return (SCENARIOS / name / "evidence" / "access.log").read_bytes()


@pytest.mark.parametrize("seed", range(40))
def test_damaged_evidence_still_gives_a_sound_report(seed, tmp_path):
    rng = random.Random(seed)
    name = rng.choice(NAMES)
    log = damage_log(_original(name), rng)
    manifest = None
    if rng.random() < 0.4:
        manifest = damage_manifest(_case(name)[0].manifest.read_bytes(), rng)
    first = render(_run(tmp_path, name, log, manifest=manifest), OFFSET, strict=True)
    again = render(_run(tmp_path, name, log, manifest=manifest), OFFSET, strict=True)
    assert first == again

    report = json.loads(first["json"])
    physical = [x.rstrip(b"\r").decode("utf-8", "backslashreplace") for x in log.split(b"\n")]
    for event in report["result"]["timeline"]:
        for c in event["citations"]:
            if c["kind"] == "log_line" and c["source"] == "access.log":
                assert physical[c["line_no"] - 1].startswith(c["excerpt"].rstrip("…")[:150])
    non_blank = sum(1 for x in log.split(b"\n") if x.strip(b"\r").strip())
    assert report["scope"]["log_events"] + report["scope"]["log_unparsed"] == non_blank


@pytest.mark.parametrize("name", NAMES)
def test_line_order_does_not_change_the_conclusions(name, tmp_path):
    lines = _original(name).split(b"\n")
    before = _conclusions(_run(tmp_path, name, b"\n".join(lines)))
    random.Random(7).shuffle(lines)
    assert _conclusions(_run(tmp_path, name, b"\n".join(lines))) == before


@pytest.mark.parametrize("name", NAMES)
def test_plain_visits_from_new_addresses_accuse_no_one(name, tmp_path):
    rng = random.Random(11)
    lines = _original(name).split(b"\n")
    before = _conclusions(_run(tmp_path, name, b"\n".join(lines)))
    stamps = [x.split(b"[", 1)[1][:26] for x in lines if b"[" in x]
    for _ in range(40):
        ip = f"198.51.{rng.randint(0, 255)}.{rng.randint(1, 254)}".encode()
        path = rng.choice([b"/", b"/about.php", b"/css/site.css", b"/img/logo.png",
                           b"/index.php", b"/product.php?id=3"])
        lines.insert(rng.randrange(len(lines) + 1),
                     ip + b" - - [" + rng.choice(stamps) + b'] "GET ' + path
                     + b' HTTP/1.1" 200 512 "-" "Mozilla/5.0"')
    ips, affected, scripts = _conclusions(_run(tmp_path, name, b"\n".join(lines)))
    assert ips <= before[0] and (affected, scripts) == before[1:]


def test_a_gzip_log_cut_short_keeps_what_can_be_read(tmp_path):
    report = _run(tmp_path, "a", cut_gzip(_original("a") * 50), gz=True)
    failures = [g for g in report.result.gaps if g.kind.value == "parse_errors"]
    assert failures, "the unreadable rest must show as a gap"
    assert report.scope.log_events > 0


def test_a_manifest_time_out_of_range_is_a_bad_row_not_a_crash():
    header = "#webforensics-manifest v1\n#columns=path_hex,type,size,mode,uid,inode,atime," \
             "mtime,ctime,btime,sha256\n"
    # 1e308 is out of range everywhere; 99999999999 (year 5138) only on Windows.
    row = "\t".join(["612e706870", "f", "1", "644", "33", "1", "0", "1e308", "0", "0",
                     "a" * 64])
    _, entries, failures = parse_manifest((header + row + "\n").splitlines(True), "m.tsv")
    assert entries == [] and [f.reason for f in failures] == ["timestamp_out_of_range"]


NL = b"\n"


def _summary_keys(report) -> list[str]:
    return [r.key for r in report.summary]


def test_an_unreadable_log_is_said_first_not_read_as_nothing_found(tmp_path):
    garbage = NL.join(b'{"json":' + x for x in _original("a").split(NL) if x)
    keys = _summary_keys(_run(tmp_path, "a", garbage))
    assert keys[0] == "summary.log_unreadable"


def test_a_mostly_unreadable_log_is_flagged(tmp_path):
    lines = _original("a").split(NL)
    damaged = NL.join(lines[:2] + [b"junk"] * 5 + lines[2:])
    assert _summary_keys(_run(tmp_path, "a", damaged))[0] == "summary.log_mostly_unreadable"


def test_a_few_bad_lines_do_not_raise_the_warning(tmp_path):
    lines = _original("a").split(NL) * 5 + [b"junk"]
    assert not any(k.startswith("summary.log_")
                   for k in _summary_keys(_run(tmp_path, "a", NL.join(lines))))

