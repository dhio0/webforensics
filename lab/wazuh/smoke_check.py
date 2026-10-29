"""Live, read-only Wazuh checks for the scenario A lab, with one inert-marker delete."""

from __future__ import annotations

import base64
import datetime as dt
import http.client
import json
import re
import socket
import ssl
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from urllib import error, request

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ENV_FILE = HERE / ".env"
CA_FILE = HERE / ".upstream" / "single-node" / "config" / "wazuh_indexer_ssl_certs" / "root-ca.pem"
COMPOSE = ROOT / "lab" / "docker-compose.yml"


class LocalIndexerHTTPSConnection(http.client.HTTPSConnection):
    """Use host loopback for TCP and retain hostname verification for the cert SAN."""

    def connect(self) -> None:
        raw = socket.create_connection(("127.0.0.1", self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class LocalIndexerHTTPSHandler(request.HTTPSHandler):
    def https_open(self, req: request.Request):
        return self.do_open(LocalIndexerHTTPSConnection, req, context=self._context)


def env_values() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def api(
    path: str, *, method: str = "GET", body: object | None = None
) -> tuple[int, dict[str, object]]:
    credentials = env_values()
    auth = base64.b64encode(
        f"webforensics_reader:{credentials['WAZUH_READER_PASSWORD']}".encode()
    ).decode()
    data = None if body is None else json.dumps(body).encode()
    req = request.Request(
        f"https://wazuh.indexer:9200/{path.lstrip('/')}",
        data=data,
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        method=method,
    )
    try:
        opener = request.build_opener(
            LocalIndexerHTTPSHandler(context=ssl.create_default_context(cafile=str(CA_FILE)))
        )
        with opener.open(req, timeout=20) as res:
            return res.status, json.loads(res.read() or b"{}")
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            parsed = {"body": payload}
        return exc.code, parsed


def search(index: str, query: dict[str, object], *, size: int = 100) -> list[dict[str, object]]:
    status, data = api(
        f"{index}/_search",
        method="POST",
        body={"size": size, "query": query, "sort": [{"timestamp": "asc"}, {"_id": "asc"}]},
    )
    if status != 200:
        raise RuntimeError(f"search {index} returned HTTP {status}: {data}")
    return data.get("hits", {}).get("hits", [])  # type: ignore[union-attr,return-value]


def command(*args: str) -> str:
    return subprocess.run(args, check=True, cwd=ROOT, capture_output=True, text=True).stdout.strip()


def parse_log_time(line: str) -> dt.datetime:
    match = re.search(r"\[([^\]]+)\]", line)
    if not match:
        raise RuntimeError("could not read nginx access-log timestamp")
    return dt.datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")


def since_filter(start: dt.datetime) -> list[dict[str, object]]:
    """Limit FIM queries to this replay's agent and time; older replays stay indexed."""
    iso = (start - dt.timedelta(seconds=5)).astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return [
        {"term": {"agent.name": "wf-lab-agent"}},
        {"range": {"timestamp": {"gte": iso}}},
    ]


def parse_alert_time(source: dict[str, object]) -> dt.datetime:
    return dt.datetime.fromisoformat(str(source["timestamp"]).replace("Z", "+00:00"))


def main() -> int:
    access_log = ROOT / "lab" / "logs" / "access.log"
    raw_lines = access_log.read_bytes().split(b"\n")
    if raw_lines and raw_lines[-1] == b"":
        raw_lines.pop()
    if not raw_lines:
        raise RuntimeError("lab/logs/access.log is empty; run Scenario A with WF_LAB_WAZUH=1 first")
    access_count = len(raw_lines)
    lines = [line.removesuffix(b"\r") for line in raw_lines]
    status, archive_data = api(
        "wazuh-archives-4.x-*/_search",
        method="POST",
        body={
            "size": max(100, access_count + 10),
            "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"location": "/var/log/nginx/access.log"}},
                        {"exists": {"field": "full_log"}},
                        {
                            "bool": {
                                "should": [
                                    {"match_phrase": {"full_log": line.decode("utf-8")}}
                                    for line in lines
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                    ]
                }
            },
        },
    )
    if status != 200:
        raise RuntimeError(f"archive access-event search returned HTTP {status}: {archive_data}")
    archive_hits = archive_data.get("hits", {}).get("hits", [])  # type: ignore[union-attr]
    archive_lines = [
        str(hit.get("_source", {}).get("full_log", "")).encode("utf-8") for hit in archive_hits
    ]
    expected_counter = Counter(lines)
    actual_counter = Counter(archive_lines)
    exact_count = sum((expected_counter & actual_counter).values())
    first_mismatch = next(
        (
            (expected, actual)
            for expected, actual in zip(lines, archive_lines, strict=False)
            if expected != actual
        ),
        None,
    )
    if first_mismatch is None and len(lines) != len(archive_lines):
        first_mismatch = (
            (lines[min(len(lines), len(archive_lines)) :] or [b"<none>"])[0],
            (archive_lines[min(len(lines), len(archive_lines)) :] or [b"<none>"])[0],
        )
    archive_equal = expected_counter == actual_counter
    print(
        f"1. Access log vs archive full_log: access_count={access_count}; "
        f"archive_count={len(archive_lines)}; exact_multiset_matches={exact_count}; "
        f"equal={archive_equal}; first_mismatch={first_mismatch!r}"
    )

    marker = "/var/www/html/uploads/lab-marker.php"
    replay_start = parse_log_time(lines[0].decode("utf-8", errors="replace"))
    fim_hits = search(
        "wazuh-alerts-4.x-*",
        {"bool": {"must": [{"term": {"syscheck.path": marker}}, *since_filter(replay_start)]}},
        size=100,
    )
    marker_added_hits = [
        hit
        for hit in fim_hits
        if hit.get("_source", {}).get("syscheck", {}).get("event") == "added"
    ]
    # search() sorts ascending and only this replay's alerts match; take the latest.
    marker_added = marker_added_hits[-1] if marker_added_hits else None
    if marker_added is None:
        raise RuntimeError(f"no FIM added event found for {marker}; hits={fim_hits}")
    source = marker_added["_source"]
    syscheck = source["syscheck"]
    agent_hash = command(
        "docker", "compose", "-f", str(COMPOSE), "exec", "-T", "php", "sha256sum", marker
    )
    current_hash = agent_hash.split()[0]
    # Compare the FIM event to the exact bytes in the shared webroot volume.
    hash_matches = syscheck.get("sha256_after") == current_hash
    print(
        f"2. Marker FIM: event={syscheck.get('event')}; mode={syscheck.get('mode')}; "
        f"sha256_after={syscheck.get('sha256_after')}; live_webroot_sha256={current_hash}; "
        f"hash_matches={hash_matches}"
    )

    upload_line = next(
        (
            line.decode("utf-8", errors="replace")
            for line in lines
            if b'"POST /admin/upload.php ' in line
        ),
        None,
    )
    if upload_line is None:
        raise RuntimeError("Scenario A upload POST not found in access.log")
    delay = (parse_alert_time(source) - parse_log_time(upload_line)).total_seconds()
    print(f"3. Upload-request to FIM alert delay: {delay:.3f} seconds")

    delete_start = dt.datetime.now(dt.UTC)
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), "exec", "-T", "php", "rm", "-f", marker],
        check=True,
        cwd=ROOT,
    )
    deleted = None
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and deleted is None:
        deleted_hits = search(
            "wazuh-alerts-4.x-*",
            {
                "bool": {
                    "must": [
                        {"term": {"syscheck.path": marker}},
                        {"term": {"syscheck.event": "deleted"}},
                        *since_filter(delete_start),
                    ]
                }
            },
            size=50,
        )
        deleted = deleted_hits[-1] if deleted_hits else None
        if deleted is None:
            time.sleep(2)
    if deleted is None:
        raise RuntimeError("timed out waiting for the lab-only deleted-marker FIM event")
    deleted_source = deleted["_source"]["syscheck"]
    print(
        f"4. Lab-only deleted marker event: event={deleted_source.get('event')}; "
        f"sha256_after_present={'sha256_after' in deleted_source}; "
        f"sha256_after={deleted_source.get('sha256_after')}"
    )

    mtime = str(syscheck.get("mtime_after", ""))
    alert_ts = str(source.get("timestamp", ""))
    raw_naive = (
        dt.datetime.fromisoformat(mtime)
        if mtime and not re.search(r"[+-]\d\d:?\d\d$", mtime)
        else None
    )
    alert_dt = parse_alert_time(source)
    mtime_dt = (
        raw_naive.replace(tzinfo=alert_dt.tzinfo)
        if raw_naive
        else dt.datetime.fromisoformat(mtime.replace("Z", "+00:00"))
    )
    offset = (mtime_dt.utcoffset() or dt.timedelta()).total_seconds() / 3600
    print(
        f"5. Raw _source.syscheck.mtime_after={mtime}; alert timestamp={alert_ts}; "
        f"manager UTC offset applied={offset:+.0f}h; "
        f"difference={(alert_dt - mtime_dt).total_seconds():.3f}s"
    )

    index_name = str(marker_added["_index"])
    write_path = f"{index_name}/_doc/wf-lab-reader-write-probe"
    write_status, _write_result = api(
        write_path, method="PUT", body={"probe": "lab-only; must be rejected"}
    )
    if write_status == 201:
        admin = env_values()
        auth = base64.b64encode(f"admin:{admin['WAZUH_ADMIN_PASSWORD']}".encode()).decode()
        req = request.Request(
            f"https://wazuh.indexer:9200/{write_path}",
            headers={"Authorization": f"Basic {auth}"},
            method="DELETE",
        )
        opener = request.build_opener(
            LocalIndexerHTTPSHandler(context=ssl.create_default_context(cafile=str(CA_FILE)))
        )
        with opener.open(req, timeout=10):
            pass
    delete_status, _delete_result = api(
        f"{index_name}/_doc/wf-lab-reader-delete-probe", method="DELETE"
    )
    reader_write_checks_passed = write_status == 403 and delete_status == 403
    print(
        f"6. Reader write attempts: create HTTP {write_status} (403 expected); "
        f"delete HTTP {delete_status} (403 expected); "
        f"both rejected={reader_write_checks_passed}"
    )

    pit_status, pit_data = api(
        "wazuh-archives-4.x-*/_search/point_in_time?keep_alive=1m", method="POST"
    )
    pit_id = pit_data.get("pit_id")
    page1: dict[str, object] = {}
    page2: dict[str, object] = {}
    page1_status = page2_status = None
    delete_pit_status = None
    if pit_status == 200 and pit_id:
        page1_status, page1 = api(
            "_search",
            method="POST",
            body={
                "size": 2,
                "query": {"match_all": {}},
                "pit": {"id": pit_id, "keep_alive": "1m"},
                "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
            },
        )
        hits1 = page1.get("hits", {}).get("hits", []) if page1_status == 200 else []  # type: ignore[union-attr]
        if page1_status == 200 and hits1:
            last_sort = hits1[-1].get("sort")
            page2_status, page2 = api(
                "_search",
                method="POST",
                body={
                    "size": 2,
                    "query": {"match_all": {}},
                    "pit": {"id": pit_id, "keep_alive": "1m"},
                    "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
                    "search_after": last_sort,
                },
            )
        delete_pit_status, _delete_pit = api(
            "_search/point_in_time", method="DELETE", body={"pit_id": [pit_id]}
        )
    hits1 = page1.get("hits", {}).get("hits", []) if page1 else []  # type: ignore[union-attr]
    hits2 = page2.get("hits", {}).get("hits", []) if page2 else []  # type: ignore[union-attr]
    pit_works = (
        pit_status == 200
        and bool(pit_id)
        and page1_status == 200
        and bool(hits1)
        and page2_status == 200
        and bool(hits2)
        and delete_pit_status == 200
    )
    print(
        f"7. Reader PIT pagination: create_http={pit_status}; page1_http={page1_status}; "
        f"page1_hits={len(hits1)}; page2_http={page2_status}; page2_hits={len(hits2)}; "
        f"delete_http={delete_pit_status}; works={pit_works}"
    )

    stats = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.Name}}={{.MemUsage}}"],
        check=True,
        cwd=ROOT,
        capture_output=True,
        text=True,
    ).stdout.strip()
    print("8. docker stats --no-stream memory:\n" + (stats or "(no running containers)"))
    failures = []
    if not archive_equal:
        failures.append("archive full_log values do not match access.log byte-for-byte")
    if not hash_matches:
        failures.append("marker FIM sha256_after does not match the live webroot")
    if deleted is None:
        failures.append("deleted-marker FIM event is missing")
    if not reader_write_checks_passed:
        failures.append("read-only create/delete attempts did not both return HTTP 403")
    if not pit_works:
        failures.append("PIT create, search_after pagination, or delete failed")
    if failures:
        raise RuntimeError("Smoke checks failed: " + "; ".join(failures))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Wazuh smoke check failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
