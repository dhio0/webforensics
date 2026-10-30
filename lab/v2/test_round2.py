"""Focused tests for the evidence-integrity fixes required before recording."""

from __future__ import annotations

import hashlib
import io
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest
from cryptography.exceptions import InvalidTag
from lab.v2 import background, collect, crypto, decrypt, label, validate_evidence

from webforensics.adapters.file_adapter import LogFileSource, ManifestFileSource


def manifest_row(path: Path, root: Path, inode: int) -> collect.ManifestRow:
    rel = path.relative_to(root).as_posix()
    payload = path.read_bytes()
    sha = hashlib.sha256(payload).hexdigest()
    fields = (
        rel.encode("utf-8").hex(), "f", str(len(payload)), "644", "1000", str(inode),
        "1", "2", "3", "0", sha,
    )
    return collect.ManifestRow(rel, "f", fields, sha)


def test_ip_mapping_has_no_collisions_for_50000_sources(tmp_path: Path) -> None:
    mapper = background.IPMapper(seed=17)
    start = int(background.ipaddress.ip_address("198.18.0.0"))
    source_addresses = (
        str(background.ipaddress.ip_address(start + i + 1)) for i in range(50_000)
    )
    mapped = [mapper.assign(source_ip) for source_ip in source_addresses]

    assert len(mapped) == len(set(mapped)) == 50_000
    assert all(
        background.ipaddress.ip_address(ip) not in network
        for ip in mapped
        for network in (background.ATTACKER_NETWORK, *background.LAB_NETWORKS)
    )
    first_seen = list(mapper.mapping.items())
    assert [ip for ip, _ in first_seen[:3]] == ["198.18.0.1", "198.18.0.2", "198.18.0.3"]
    out = tmp_path / "ip_map.tsv"
    mapper.write_tsv(out)
    assert out.read_text(encoding="ascii").splitlines()[1] == "source_ip\tmapped_ip"


def test_gcm_round_trip_authenticates_harmless_file(tmp_path: Path) -> None:
    original = tmp_path / "plain.txt"
    original.write_text("harmless round trip\n", encoding="utf-8")
    encrypted = tmp_path / "capture.enc"
    restored = tmp_path / "restored.txt"
    key = bytes(range(32))

    crypto.encrypt_file(original, encrypted, key, nonce=bytes(range(12)))
    crypto.decrypt_file(encrypted, restored, key)

    assert restored.read_bytes() == original.read_bytes()
    damaged = bytearray(encrypted.read_bytes())
    damaged[-1] ^= 1
    with pytest.raises(InvalidTag):
        crypto.decrypt_bytes(bytes(damaged), key)


def test_decrypt_refuses_repository_and_escaping_tar_members(tmp_path: Path) -> None:
    full_dir = tmp_path / "full"
    scenario_dir = full_dir / "s01"
    scenario_dir.mkdir(parents=True)
    encrypted = scenario_dir / "full-evidence.tar.gz.enc"
    key = bytes(range(32))
    archive = tmp_path / "escape.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("../escape.txt")
        payload = b"not extracted"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    crypto.encrypt_file(archive, encrypted, key, nonce=b"0" * 12)

    with pytest.raises(ValueError, match="repository"):
        decrypt.decrypt_archive(
            encrypted, tmp_path / "repo-out", tmp_path, key, repository=tmp_path
        )
    with pytest.raises(ValueError, match="unsafe tar member"):
        decrypt.decrypt_archive(
            encrypted, scenario_dir / "decrypted", full_dir, key, repository=tmp_path / "repo"
        )


def test_collector_defangs_every_changed_executable_independent_of_records(tmp_path: Path) -> None:
    root = tmp_path / "webroot"
    root.mkdir()
    unchanged = root / "index.php"
    unchanged.write_text("baseline app source", encoding="ascii")
    upload = root / "unlisted.php"
    upload.write_text("attacker artifact body", encoding="ascii")
    hidden_config = root / ".htaccess"
    hidden_config.write_text("AddHandler application/x-httpd-php .jpg\n", encoding="ascii")
    disguised = root / "benign-looking.jpg"
    disguised.write_bytes(b"<?harmless test marker")
    baseline = {"index.php": manifest_row(unchanged, root, 1)}
    current = {
        path.name: manifest_row(path, root, 1 if path == unchanged else 2)
        for path in root.iterdir()
    }
    snapshot = tmp_path / "evidence" / "webroot"
    collect.defang_snapshot(root, current, baseline, snapshot, roles={})

    assert (snapshot / "index.php").read_text(encoding="ascii") == "baseline app source"
    assert (snapshot / "unlisted.php").read_text(encoding="ascii").startswith("DEFANGED ")
    assert (snapshot / ".htaccess").read_text(encoding="ascii").startswith("DEFANGED ")
    assert (snapshot / "benign-looking.jpg").read_text(encoding="ascii").startswith("DEFANGED ")
    assert "unlisted.php" in (tmp_path / "evidence" / "defanged.tsv").read_text(encoding="utf-8")


def test_collect_sh_v1_manifest_and_combined_log_load_with_fileadapter(tmp_path: Path) -> None:
    webroot = tmp_path / "webroot"
    webroot.mkdir()
    content = b"static evidence\n"
    (webroot / "index.html").write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    manifest = tmp_path / "manifest.tsv"
    manifest.write_text(
        "#webforensics-manifest v1\n"
        "#collector=collect.sh 0.2.0\n"
        "#collected_at=1793361600\n"
        "#utc_offset=+0000\n"
        "#birth_time_supported=0\n"
        "#columns=path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256\n"
        f"{b'index.html'.hex()}\tf\t{len(content)}\t644\t1000\t91\t1793361600\t"
        f"1793361600\t1793361600\t0\t{sha}\n",
        encoding="ascii",
    )
    access = tmp_path / "access.log"
    access.write_text(
        '127.0.0.1 - - [30/Oct/2026:12:00:01 +0000] '
        '"GET / HTTP/1.1" 200 2 "-" "ua" "198.51.100.1"\n',
        encoding="ascii",
    )

    files = ManifestFileSource(manifest, webroot).load_files()
    logs = LogFileSource([access]).load_logs()

    assert not files.failures
    assert not logs.failures
    assert len(files.files) == len(logs.events) == 1
    assert files.files[0].inode == 91
    assert files.files[0].btime is None


def test_evidence_validator_prints_adapter_parse_failure_counts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence = tmp_path / "evidence"
    webroot = evidence / "webroot"
    webroot.mkdir(parents=True)
    (evidence / "access.log").write_text(
        '127.0.0.1 - - [30/Oct/2026:12:00:01 +0000] '
        '"GET / HTTP/1.1" 200 2 "-" "ua" "198.51.100.1"\n',
        encoding="ascii",
    )
    (webroot / "index.html").write_text("ok\n", encoding="ascii")
    content = (webroot / "index.html").read_bytes()
    (evidence / "manifest.tsv").write_text(
        "#webforensics-manifest v1\n"
        "#columns=path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256\n"
        f"{b'index.html'.hex()}\tf\t{len(content)}\t644\t1000\t91\t1\t2\t3\t0\t"
        f"{hashlib.sha256(content).hexdigest()}\n",
        encoding="ascii",
    )

    assert validate_evidence.validate(evidence) == (0, 0, 0)
    assert "access events=1 parse_failures=0" in capsys.readouterr().out


def test_project_manifest_parser_reads_full_metadata_for_baseline_diff(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.tsv"
    manifest.write_text(
        "#webforensics-manifest v1\n"
        "#columns=path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256\n"
        f"{b'a.php'.hex()}\tf\t4\t755\t1000\t88\t1\t2\t3\t4\t{'a' * 64}\n",
        encoding="ascii",
    )
    row = label.parse_manifest(manifest)["a.php"]

    assert row["mode"] == "755"
    assert row["inode"] == "88"
    assert row["btime"] == "4"
    assert row["sha256"] == "a" * 64


def test_label_join_requires_request_status_client_and_time(tmp_path: Path) -> None:
    when = datetime(2026, 10, 30, 12, 0, 1, tzinfo=UTC)
    access = tmp_path / "access.log"
    access.write_text(
        '10.0.0.2 - - [30/Oct/2026:12:00:01 +0000] '
        '"GET /x HTTP/1.1" 200 3 "-" "ua" "198.51.100.1"\n',
        encoding="ascii",
    )
    rows = label.access_index(access)
    matched = label.join_sidecar_request(
        {
            "sidecar_line": 1,
            "msec": when.timestamp(),
            "request": "GET /x HTTP/1.1",
            "status": 200,
            "client_ip": "198.51.100.1",
        },
        rows,
        set(),
    )
    assert matched["line_no"] == 1
    with pytest.raises(ValueError, match="refusing positional join"):
        label.join_sidecar_request(
            {
                "sidecar_line": 2,
                "msec": when.timestamp(),
                "request": "GET /other HTTP/1.1",
                "status": 200,
                "client_ip": "198.51.100.1",
            },
            rows,
            set(),
        )


def test_edge_plain_log_is_combined_and_drops_custom_headers_upstream() -> None:
    config = (Path(__file__).parent / "nginx" / "edge.conf").read_text(encoding="utf-8")
    plain_format = config.split("log_format plain_combined_xff", 1)[1].split(";", 1)[0]
    assert "$http_x_lab_step" not in plain_format
    assert "plain_combined_xff" in config
    assert "replay_labels" in config and "$http_x_lab_step" in config
    assert config.count("proxy_pass_request_headers off;") == 3


def test_background_posts_have_empty_body_and_redirects_are_disabled() -> None:
    request = background.Request(
        background.target_url("/post", "wp"),
        data=b"",
        method="POST",
    )
    assert request.data == b""
    assert background.target_url("/home", "wp").startswith("http://edge/wp/")
    with pytest.raises(ValueError):
        background.target_url("https://example.org/", "wp")
    assert (
        background.NoRedirects().redirect_request(
            None, None, 302, "", {}, "https://example.org"
        )
        is None
    )


def test_background_thread_records_timing_and_network_failure_kinds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "requests.log"
    source.write_text(
        "".join(
            f'198.18.0.{i} - - [30/Oct/2026:12:00:0{i} +0000] '
            f'"GET /item HTTP/1.1" 200 1 "-" "agent-{i}"\n'
            for i in range(1, 5)
        ),
        encoding="ascii",
    )

    class FakeOpener:
        def __init__(self) -> None:
            self.errors = [
                TimeoutError("timed out"),
                ConnectionError("refused"),
                URLError(TimeoutError("wrapped timeout")),
                HTTPError("http://edge/wp/", 404, "missing", {}, None),
            ]

        def open(self, request, timeout):
            assert request.full_url.startswith("http://edge/wp/")
            assert timeout == 1
            raise self.errors.pop(0)

    monkeypatch.setattr(background, "build_opener", lambda *args: FakeOpener())
    replay = background.BackgroundReplay(source, "wp", timeout=1, pace=0, seed=9).start()
    stats = replay.join(timeout=2)

    assert stats.attempted == 4
    assert stats.failures == {
        "connection_error": 1,
        "http_error": 1,
        "timeout": 2,
    }
    assert stats.started_at is not None and stats.ended_at is not None
    assert len(replay.ip_mapper.mapping) == 4
