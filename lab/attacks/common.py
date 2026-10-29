"""Small helpers shared by the fixed, localhost-only scenario replays."""

import base64
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib import error, request

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "lab" / "docker-compose.yml"
STEP_DELAY_SECONDS = 2
WAZUH_ENABLED = os.environ.get("WF_LAB_WAZUH", "").strip().lower() in {"1", "true", "yes", "on"}
WAZUH_DIR = ROOT / "lab" / "wazuh"
_BASELINE_MANIFEST: dict[str, str] = {}
# Alerts from earlier replays stay indexed, so FIM waits only accept events after this time.
_SCENARIO_START_UTC = ""


class _LocalIndexerHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the loopback-published indexer while verifying its DNS certificate name."""

    def connect(self) -> None:
        raw = socket.create_connection(("127.0.0.1", self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class _LocalIndexerHTTPSHandler(request.HTTPSHandler):
    def https_open(self, req: request.Request):
        return self.do_open(_LocalIndexerHTTPSConnection, req, context=self._context)


def _wazuh_env() -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in (WAZUH_DIR / ".env").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def _wazuh_request(path: str, body: dict[str, object]) -> dict[str, object]:
    credentials = _wazuh_env()
    password = credentials["WAZUH_READER_PASSWORD"]
    authorization = base64.b64encode(f"webforensics_reader:{password}".encode()).decode()
    ca = (
        WAZUH_DIR
        / ".upstream"
        / "single-node"
        / "config"
        / "wazuh_indexer_ssl_certs"
        / "root-ca.pem"
    )
    context = ssl.create_default_context(cafile=str(ca))
    req = request.Request(
        f"https://wazuh.indexer:9200/{path.lstrip('/')}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Basic {authorization}", "Content-Type": "application/json"},
        method="POST",
    )
    opener = request.build_opener(_LocalIndexerHTTPSHandler(context=context))
    with opener.open(req, timeout=8) as response:
        return json.loads(response.read())


def compose(*args: str) -> None:
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), *args],
        check=True,
        cwd=ROOT,
    )


def _mysql_ready() -> bool:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE),
            "exec",
            "-T",
            "php",
            "php",
            "-r",
            "$p=new PDO('mysql:host=mysql;dbname=lab','lab','lab-only-password');",
        ],
        cwd=ROOT,
        capture_output=True,
    )
    return result.returncode == 0


def start_fresh_lab() -> None:
    """Remove this compose project's volumes, then start an empty lab state."""
    if WAZUH_ENABLED:
        subprocess.run(
            [sys.executable, str(WAZUH_DIR / "setup.py"), "up"],
            check=True,
            cwd=ROOT,
        )
    if WAZUH_ENABLED:
        compose("--profile", "wazuh", "down", "-v")
    else:
        compose("down", "-v")
    if WAZUH_ENABLED:
        # The agent starts after truncation so only this replay's log lines are collected.
        for log in (ROOT / "lab" / "logs" / "access.log", ROOT / "lab" / "logs" / "error.log"):
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text("", encoding="utf-8")
        compose("--profile", "wazuh", "up", "-d", "--build")
    else:
        compose("up", "-d", "--build")
    # MySQL's ping healthcheck can pass while initialization is still completing.
    for attempt in range(30):
        if _mysql_ready():
            break
        if attempt < 29:
            time.sleep(1)
    else:
        raise RuntimeError("lab MySQL did not become ready for PHP requests")
    if WAZUH_ENABLED:
        _wait_agent_ready()
        global _SCENARIO_START_UTC
        # 5 s slack covers small host/VM clock skew; earlier replays are minutes older.
        _SCENARIO_START_UTC = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 5))
        _BASELINE_MANIFEST.clear()
        _BASELINE_MANIFEST.update(_webroot_manifest())
    else:
        compose(
            "exec",
            "-T",
            "nginx",
            "sh",
            "-c",
            "truncate -s 0 /var/log/nginx/access.log /var/log/nginx/error.log && nginx -s reopen",
        )


def _wait_agent_ready(timeout: int = 240) -> None:
    """Wait for baseline, active realtime FIM, and both logcollector inputs."""
    deadline = time.monotonic() + timeout
    scan_done = False
    realtime_started = False
    realtime_directory = False
    logs_ready = False
    last_output = ""
    while time.monotonic() < deadline:
        result = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE),
                "exec",
                "-T",
                "wazuh-agent",
                "sh",
                "-c",
                "cat /var/ossec/logs/ossec.log",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            last_output = result.stdout
            # 4.14.9 information_messages.h defines the exact scan-end and realtime-start text:
            # "(6009): File integrity monitoring scan ended." and
            # "(6012): Real-time file integrity monitoring started."
            # https://github.com/wazuh/wazuh/blob/v4.14.9/src/error_messages/information_messages.h
            scan_done = "File integrity monitoring scan ended." in last_output
            realtime_started = "(6012): Real-time file integrity monitoring started." in last_output
            realtime_directory = (
                "(6016): Directory set for real time monitoring: '/var/www/html'." in last_output
                or ("Monitoring path: '/var/www/html'" in last_output and "realtime" in last_output)
            )
            logs_ready = all(
                f"Analyzing file: '/var/log/nginx/{name}'" in last_output
                for name in ("access.log", "error.log")
            )
            if scan_done and realtime_started and realtime_directory and logs_ready:
                return
        time.sleep(2)
    raise RuntimeError(
        "Wazuh agent did not finish its initial FIM scan, activate realtime FIM for "
        "'/var/www/html', and start reading nginx logs "
        f"within {timeout}s (scan_done={scan_done}, realtime_started={realtime_started}, "
        f"realtime_directory={realtime_directory}, logs_ready={logs_ready}). "
        f"Latest agent log tail: {last_output[-1800:]}"
    )


def _webroot_manifest() -> dict[str, str]:
    """Return relative file paths and SHA-256 values from the live PHP webroot."""
    script = (
        "$root='/var/www/html'; $out=[]; "
        "$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, "
        "FilesystemIterator::SKIP_DOTS)); "
        "foreach($it as $f){if($f->isFile()){ $p=substr($f->getPathname(), strlen($root)+1); "
        "$h=hash_file('sha256',$f->getPathname()); if($h!==false){$out[$p]=$h;}}} "
        "ksort($out); echo json_encode($out, JSON_UNESCAPED_SLASHES);"
    )
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), "exec", "-T", "php", "php", "-r", script],
        check=True,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("PHP webroot manifest returned invalid JSON")
    return {str(path): str(sha256) for path, sha256 in value.items()}


def finish_scenario() -> None:
    """Wait until final archive and all scenario FIM changes are indexed."""
    if not WAZUH_ENABLED:
        return
    access_log = ROOT / "lab" / "logs" / "access.log"
    lines = access_log.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        raise RuntimeError("Wazuh replay finished with no nginx access-log lines")
    last_line = lines[-1]
    deadline = time.monotonic() + 120
    last_error = "not queried"
    archive_found = False
    while time.monotonic() < deadline:
        try:
            result = _wazuh_request(
                "wazuh-archives-4.x-*/_search",
                {"size": 1, "query": {"match_phrase": {"full_log": last_line}}},
            )
            hits = result.get("hits", {}).get("hits", [])  # type: ignore[union-attr]
            if hits:
                print("Final scenario access-log line is searchable in wazuh-archives-4.x-*")
                archive_found = True
                break
        except Exception as exc:
            last_error = str(exc)
        time.sleep(2)
    if not archive_found:
        raise RuntimeError(
            f"Last access-log line did not reach Wazuh archives within 120s: {last_error}"
        )
    after = _webroot_manifest()
    paths = sorted(
        path
        for path in set(_BASELINE_MANIFEST) | set(after)
        if _BASELINE_MANIFEST.get(path) != after.get(path)
    )
    print(f"Scenario webroot changed paths: {paths}")
    if not paths:
        return
    missing = {}
    for path in paths:
        if path not in _BASELINE_MANIFEST:
            missing[path] = "added"
        elif path not in after:
            missing[path] = "deleted"
        else:
            missing[path] = "modified"
    fim_deadline = time.monotonic() + 180
    last_fim_error = "not queried"
    while time.monotonic() < fim_deadline and missing:
        for path, event in list(missing.items()):
            try:
                result = _wazuh_request(
                    "wazuh-alerts-4.x-*/_search",
                    {
                        "size": 1,
                        "query": {
                            "bool": {
                                "must": [
                                    {"term": {"syscheck.path": f"/var/www/html/{path}"}},
                                    {"term": {"syscheck.event": event}},
                                    {"term": {"agent.name": "wf-lab-agent"}},
                                    {"range": {"timestamp": {"gte": _SCENARIO_START_UTC}}},
                                ]
                            }
                        },
                    },
                )
                hits = result.get("hits", {}).get("hits", [])  # type: ignore[union-attr]
                if hits:
                    del missing[path]
            except Exception as exc:
                last_fim_error = str(exc)
        if missing:
            time.sleep(2)
    if missing:
        details = ", ".join(f"{path} ({event})" for path, event in missing.items())
        raise RuntimeError(
            f"Timed out waiting 180s for indexed syscheck events for changed paths: {details}. "
            f"Last query error: {last_fim_error}"
        )
    print("All changed webroot paths have matching syscheck events in wazuh-alerts-4.x-*")


def lab_request(
    opener: request.OpenerDirector,
    path: str,
    client_ip: str,
    *,
    user_agent: str,
    data: bytes | None = None,
    content_type: str | None = None,
    status: int = 200,
) -> bytes:
    """Send one scripted request through the loopback edge and check its status."""
    headers = {"User-Agent": user_agent, "X-Lab-Client-IP": client_ip}
    if content_type:
        headers["Content-Type"] = content_type
    req = request.Request(f"http://127.0.0.1:8081{path}", data=data, headers=headers)
    try:
        with opener.open(req, timeout=10) as response:
            actual_status = response.status
            body = response.read()
    except error.HTTPError as response:
        actual_status = response.code
        body = response.read()
    except error.URLError as exc:
        raise RuntimeError(f"localhost lab request failed for {path}: {exc}") from exc
    if actual_status != status:
        raise RuntimeError(
            f"expected HTTP {status}, received {actual_status} for localhost lab request {path}"
        )
    return body


def multipart_file(
    field: str,
    filename: str,
    content: bytes,
    content_type: str,
    *,
    boundary: str = "----webforensics-lab-multipart",
) -> tuple[bytes, str]:
    """Build one deterministic multipart file request body and its header value."""
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'
    ).encode()
    body += content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def collect_baseline(scenario: str) -> None:
    """Save the pristine webroot manifest before a scenario sends any requests."""
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "lab" / "collect_scenario.py"),
            "--scenario",
            scenario,
            "--baseline-only",
        ],
        check=True,
        cwd=ROOT,
    )
