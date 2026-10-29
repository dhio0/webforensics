"""Prepare and run the pinned, single-node Wazuh lab stack."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib import request

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
UPSTREAM = HERE / ".upstream"
SINGLE_NODE = UPSTREAM / "single-node"
RUNTIME = HERE / ".runtime"
INPUT_HASH_FILE = RUNTIME / "config-inputs.sha256"
ENV_FILE = HERE / ".env"
VERSION = (HERE / "VERSION").read_text(encoding="utf-8").strip()  # git tag, e.g. v4.14.9
IMAGE_TAG = VERSION.removeprefix("v")  # Docker Hub tags have no "v", e.g. 4.14.9
REPO_URL = "https://github.com/wazuh/wazuh-docker.git"

PASSWORD_KEYS = {
    "admin": "WAZUH_ADMIN_PASSWORD",
    "kibanaserver": "WAZUH_KIBANASERVER_PASSWORD",
    "kibanaro": "WAZUH_KIBANARO_PASSWORD",
    "logstash": "WAZUH_LOGSTASH_PASSWORD",
    "readall": "WAZUH_READALL_PASSWORD",
    "snapshotrestore": "WAZUH_SNAPSHOTRESTORE_PASSWORD",
}
EXTRA_KEYS = ("WAZUH_API_PASSWORD", "WAZUH_READER_PASSWORD")


class _LocalIndexerHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        raw = socket.create_connection(("127.0.0.1", self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class _LocalIndexerHTTPSHandler(request.HTTPSHandler):
    def https_open(self, req: request.Request):
        return self.do_open(_LocalIndexerHTTPSConnection, req, context=self._context)


def run(
    args: list[str], *, cwd: Path = ROOT, capture: bool = False, env: dict[str, str] | None = None
) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        env=env,
    )
    return result.stdout if capture else ""


def read_env() -> dict[str, str]:
    if not ENV_FILE.exists():
        values = {key: secrets.token_urlsafe(32) for key in (*PASSWORD_KEYS.values(), *EXTRA_KEYS)}
        ENV_FILE.write_text(
            "# Generated lab-only credentials. This file is gitignored.\n"
            + "".join(f"{key}={value}\n" for key, value in values.items()),
            encoding="utf-8",
        )
        print(f"Created random lab-only credentials in {ENV_FILE}")
    values: dict[str, str] = {}
    for raw in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    required = [*PASSWORD_KEYS.values(), *EXTRA_KEYS]
    missing = [key for key in required if not values.get(key) or values[key].startswith("replace-")]
    if missing:
        raise RuntimeError(f"Set lab-only values for {', '.join(missing)} in {ENV_FILE}")
    return values


def docker_vm_map_count() -> int:
    try:
        raw = run(
            ["docker", "run", "--rm", "alpine:3.21", "sysctl", "-n", "vm.max_map_count"],
            capture=True,
        )
        return int(raw.strip())
    except (subprocess.CalledProcessError, ValueError, FileNotFoundError) as exc:
        raise RuntimeError(
            "Could not read vm.max_map_count inside the Docker VM. Start Docker Desktop and retry."
        ) from exc


def ensure_prerequisites() -> None:
    current = docker_vm_map_count()
    if current < 262144:
        raise RuntimeError(
            f"Docker VM vm.max_map_count is {current}; Wazuh requires at least 262144. "
            "Set it in the Docker VM/WSL configuration, restart Docker Desktop, and retry."
        )
    if not UPSTREAM.exists():
        run(["git", "clone", "--depth", "1", "--branch", VERSION, REPO_URL, str(UPSTREAM)])
    else:
        tag = run(
            ["git", "describe", "--tags", "--exact-match", "HEAD"], cwd=UPSTREAM, capture=True
        ).strip()
        if tag != VERSION:
            raise RuntimeError(
                f"{UPSTREAM} is at {tag}, expected {VERSION}; remove the ignored checkout and retry"
            )
    RUNTIME.mkdir(exist_ok=True)
    if not (SINGLE_NODE / "config" / "wazuh_indexer_ssl_certs" / "root-ca.pem").exists():
        run(
            ["docker", "compose", "-f", "generate-indexer-certs.yml", "run", "--rm", "generator"],
            cwd=SINGLE_NODE,
        )
    network = subprocess.run(["docker", "network", "inspect", "wazuh-lab"], capture_output=True)
    if network.returncode:
        run(["docker", "network", "create", "wazuh-lab"])


def password_hash(password: str) -> str:
    env = os.environ.copy()
    env["WAZUH_HASH_PASSWORD"] = password
    output = run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/bin/bash",
            "-e",
            "WAZUH_HASH_PASSWORD",
            f"wazuh/wazuh-indexer:{IMAGE_TAG}",
            "-lc",
            # The docs show "export JAVA_HOME=/usr/share/wazuh-indexer/jdk/":
            # https://documentation.wazuh.com/4.14/user-manual/indexer-api/getting-started.html
            "export JAVA_HOME=/usr/share/wazuh-indexer/jdk "
            "OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk; "
            "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/"
            'hash.sh -p "$WAZUH_HASH_PASSWORD"',
        ],
        capture=True,
        env=env,
    )
    # hash.sh emits a labelled line followed by the bcrypt value.
    hashes = re.findall(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", output)
    if not hashes:
        raise RuntimeError("Could not extract bcrypt output from the OpenSearch hash utility")
    return hashes[-1]


# Manager-local modules the project does not use. They watch the manager container itself,
# not the lab webroot, and only add disk use, CPU and noise to wazuh-alerts / wazuh-states-*.
# The agent still sends FIM and logs; the manager analyzes them with these modules off.
# Each pattern matches the first child of the block in the pinned upstream config.
# 4.14 ossec.conf reference phrases (default in brackets):
# - vuln-detector.html: "Enables the vulnerability detection module." [yes]. Its CTI feed
#   filled about 13 GB of the wazuh_queue volume in this lab.
# - wodle-syscollector.html: "Disable the Syscollector wodle." [no]
# - sca.html: "Enables the module." [yes]
# - rootcheck.html: "Disables the execution of rootcheck." [no]
# - syscheck.html: "Indicates if the syscheck scan is disabled or not." [no]
# https://documentation.wazuh.com/4.14/user-manual/reference/ossec-conf/index.html
MANAGER_MODULES_OFF = (
    ("vulnerability-detection", r"<enabled>\s*yes\s*</enabled>", "<enabled>no</enabled>"),
    ('wodle name="syscollector"', r"<disabled>\s*no\s*</disabled>", "<disabled>yes</disabled>"),
    ("sca", r"<enabled>\s*yes\s*</enabled>", "<enabled>no</enabled>"),
    ("rootcheck", r"<disabled>\s*no\s*</disabled>", "<disabled>yes</disabled>"),
    ("syscheck", r"<disabled>\s*no\s*</disabled>", "<disabled>yes</disabled>"),
)


def _disable_manager_modules(manager_xml: str) -> str:
    for block, current, wanted in MANAGER_MODULES_OFF:
        manager_xml, count = re.subn(
            rf"(<{re.escape(block)}>\s*){current}", rf"\g<1>{wanted}", manager_xml, count=1
        )
        if count != 1:
            raise RuntimeError(f"Expected the pinned manager config to enable <{block}> once")
    return manager_xml


def _manager_modules_off(manager_xml: str) -> bool:
    return all(
        re.search(rf"<{re.escape(block)}>\s*{re.escape(wanted)}", manager_xml)
        for block, _current, wanted in MANAGER_MODULES_OFF
    )


def make_runtime_configs(values: dict[str, str]) -> None:
    hashes = {user: password_hash(values[key]) for user, key in PASSWORD_KEYS.items()}
    hashes["webforensics_reader"] = password_hash(values["WAZUH_READER_PASSWORD"])

    source_manager = SINGLE_NODE / "config" / "wazuh_cluster" / "wazuh_manager.conf"
    manager_xml = source_manager.read_text(encoding="utf-8")
    manager_xml, count = re.subn(
        r"<logall_json>\s*no\s*</logall_json>",
        "<!-- Archives setting; docs: 'The Wazuh server stores all events it receives'. "
        "https://documentation.wazuh.com/4.14/user-manual/manager/event-logging.html -->\n"
        "    <logall_json>yes</logall_json>",
        manager_xml,
        count=1,
    )
    if count != 1:
        raise RuntimeError(
            "Expected the pinned manager config to contain one <logall_json>no</logall_json>"
        )
    force = """<!-- Auth reference: 'force the insertion of an agent'.
    https://documentation.wazuh.com/4.14/user-manual/reference/ossec-conf/auth.html -->
    <force>
      <enabled>yes</enabled>
      <disconnected_time enabled=\"no\">0</disconnected_time>
      <after_registration_time>0</after_registration_time>
      <key_mismatch>yes</key_mismatch>
    </force>"""
    manager_xml, count = re.subn(
        r"(?m)^\s*<purge>yes</purge>", f"    {force}\n    <purge>yes</purge>", manager_xml, count=1
    )
    if count != 1:
        raise RuntimeError(
            "Could not insert documented auth replacement settings into manager config"
        )
    manager_xml = _disable_manager_modules(manager_xml)
    (RUNTIME / "wazuh_manager.conf").write_text(manager_xml, encoding="utf-8")

    (RUNTIME / "filebeat-archives.sh").write_text(
        "#!/usr/bin/with-contenv bash\n"
        "# Event-logging docs: 'The Wazuh server stores all events it receives'.\n"
        "# https://documentation.wazuh.com/4.14/user-manual/manager/event-logging.html\n"
        "set -e\n"
        "sed -i '/archives:/,/enabled:/s/enabled: false/enabled: true/' "
        "/etc/filebeat/filebeat.yml\n"
        "grep -A1 'archives:' /etc/filebeat/filebeat.yml | grep -q 'enabled: true'\n",
        encoding="utf-8",
        newline="\n",
    )

    user_entries = [
        "---",
        "# Generated from lab-only .env using the OpenSearch 2.19 hash.sh utility.",
        "_meta:",
        '  type: "internalusers"',
        "  config_version: 2",
        "",
    ]
    for user, hashed in hashes.items():
        user_entries.extend(
            [
                f"{user}:",
                f'  hash: "{hashed}"',
                f"  reserved: {'true' if user in {'admin', 'kibanaserver'} else 'false'}",
            ]
        )
        if user == "admin":
            user_entries.extend(
                ['  backend_roles: ["admin"]', '  description: "Lab administrator"']
            )
        elif user == "kibanaro":
            user_entries.extend(
                ['  backend_roles: ["kibanauser", "readall"]', '  description: "Lab demo user"']
            )
        elif user == "logstash":
            user_entries.extend(
                ['  backend_roles: ["logstash"]', '  description: "Lab integration user"']
            )
        elif user == "readall":
            user_entries.extend(['  backend_roles: ["readall"]', '  description: "Lab demo user"'])
        elif user == "snapshotrestore":
            user_entries.extend(
                ['  backend_roles: ["snapshotrestore"]', '  description: "Lab demo user"']
            )
        elif user == "webforensics_reader":
            user_entries.extend(
                [
                    '  backend_roles: ["webforensics_reader"]',
                    '  description: "Read-only Web Forensics lab user"',
                ]
            )
        else:
            user_entries.append('  description: "Lab service user"')
        user_entries.append("")
    (RUNTIME / "internal_users.yml").write_text("\n".join(user_entries), encoding="utf-8")

    security_dir = UPSTREAM / "build-docker-images" / "wazuh-indexer" / "config"
    roles = (security_dir / "roles.yml").read_text(encoding="utf-8")
    roles += """
# OpenSearch 2.19 group doc: 'read permissions on the index such as search'.
# https://docs.opensearch.org/2.19/security/access-control/default-action-groups/
# OpenSearch 2.19 PIT doc: 'Creates a PIT' and 'Deletes one, several, or all PITs'.
# https://docs.opensearch.org/2.19/api-reference/search-apis/point-in-time-api/
webforensics_reader:
  reserved: true
  hidden: false
  cluster_permissions: []
  index_permissions:
    - index_patterns:
        - 'wazuh-alerts-4.x-*'
        - 'wazuh-archives-4.x-*'
      allowed_actions:
        - 'read'
        - 'indices:data/read/point_in_time/create'
        - 'indices:data/read/point_in_time/delete'
        - 'indices:data/read/search'
"""
    (RUNTIME / "roles.yml").write_text(roles, encoding="utf-8")
    mappings = (security_dir / "roles_mapping.yml").read_text(encoding="utf-8")
    mappings += """
webforensics_reader:
  reserved: true
  hidden: false
  backend_roles:
    - 'webforensics_reader'
  hosts: []
  users:
    - 'webforensics_reader'
  and_backend_roles: []
"""
    (RUNTIME / "roles_mapping.yml").write_text(mappings, encoding="utf-8")


def compose_args() -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        str(ENV_FILE),
        "-f",
        str(SINGLE_NODE / "docker-compose.yml"),
        "-f",
        str(HERE / "compose.override.yml"),
    ]


def stack(*args: str, capture: bool = False) -> str:
    return run([*compose_args(), *args], cwd=SINGLE_NODE, capture=capture)


def _config_digest(values: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for key in sorted(values):
        digest.update(key.encode())
        digest.update(b"\0")
        digest.update(values[key].encode())
        digest.update(b"\0")
    inputs = [
        HERE / "VERSION",
        HERE / "setup.py",
        HERE / "agent.conf",
        HERE / "compose.override.yml",
        SINGLE_NODE / "config" / "wazuh_cluster" / "wazuh_manager.conf",
        UPSTREAM / "build-docker-images" / "wazuh-indexer" / "config" / "roles.yml",
        UPSTREAM / "build-docker-images" / "wazuh-indexer" / "config" / "roles_mapping.yml",
    ]
    for path in inputs:
        digest.update(str(path.relative_to(HERE)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _runtime_config_digest() -> str:
    digest = hashlib.sha256()
    for name in (
        "wazuh_manager.conf",
        "filebeat-archives.sh",
        "internal_users.yml",
        "roles.yml",
        "roles_mapping.yml",
    ):
        path = RUNTIME / name
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _runtime_configs_valid() -> bool:
    try:
        archives_script = (RUNTIME / "filebeat-archives.sh").read_text(encoding="utf-8")
        manager = (RUNTIME / "wazuh_manager.conf").read_text(encoding="utf-8")
        users = (RUNTIME / "internal_users.yml").read_text(encoding="utf-8")
    except OSError:
        return False
    return all(
        (
            "s/enabled: false/enabled: true/" in archives_script,
            "grep -q 'enabled: true'" in archives_script,
            "<logall_json>yes</logall_json>" in manager,
            _manager_modules_off(manager),
            "webforensics_reader:" in users,
        )
    )


def _stack_healthy(values: dict[str, str], dashboard: bool) -> tuple[bool, str]:
    ca = SINGLE_NODE / "config" / "wazuh_indexer_ssl_certs" / "root-ca.pem"
    context = __import__("ssl").create_default_context(cafile=str(ca))
    credentials = read_env()
    auth = (
        __import__("base64")
        .b64encode(f"admin:{credentials['WAZUH_ADMIN_PASSWORD']}".encode())
        .decode()
    )
    try:
        state = stack("ps", "--format", "json", capture=True)
        if "wazuh.manager" not in state or "wazuh.indexer" not in state:
            return False, "manager or indexer container is not running"
        req = urllib.request.Request(
            "https://wazuh.indexer:9200/", headers={"Authorization": f"Basic {auth}"}
        )
        opener = urllib.request.build_opener(_LocalIndexerHTTPSHandler(context=context))
        with opener.open(req, timeout=4) as response:
            if response.status != 200:
                return False, f"indexer returned HTTP {response.status}"
        manager = subprocess.run(
            [
                *compose_args(),
                "exec",
                "-T",
                "wazuh.manager",
                "/var/ossec/bin/wazuh-control",
                "status",
            ],
            cwd=SINGLE_NODE,
            check=False,
            capture_output=True,
            text=True,
        )
        manager_status = manager.stdout.lower()
        required_services = (
            "wazuh-modulesd is running",
            "wazuh-logcollector is running",
            "wazuh-remoted is running",
            "wazuh-syscheckd is running",
            "wazuh-analysisd is running",
            "wazuh-execd is running",
            "wazuh-db is running",
            "wazuh-authd is running",
            "wazuh-apid is running",
        )
        stopped = [service for service in required_services if service not in manager_status]
        if stopped:
            return False, "required manager services are not running: " + ", ".join(stopped)
        filebeat = subprocess.run(
            [*compose_args(), "exec", "-T", "wazuh.manager", "pgrep", "-x", "filebeat"],
            cwd=SINGLE_NODE,
            check=False,
            capture_output=True,
            text=True,
        )
        if filebeat.returncode != 0:
            return False, "Filebeat process is not running"
        if dashboard:
            dashboard_req = urllib.request.Request("https://wazuh.dashboard:4443/")
            dashboard_opener = urllib.request.build_opener(
                _LocalIndexerHTTPSHandler(context=context)
            )
            try:
                with dashboard_opener.open(dashboard_req, timeout=4) as response:
                    if response.status >= 500:
                        return False, f"dashboard returned HTTP {response.status}"
            except urllib.error.HTTPError as exc:
                if exc.code >= 500:
                    return False, f"dashboard returned HTTP {exc.code}"
        return True, "healthy"
    except Exception as exc:
        return False, str(exc)


def up(dashboard: bool = False) -> None:
    ensure_prerequisites()
    values = read_env()
    if not dashboard:
        existing_dashboard = stack(
            "--profile", "dashboard", "ps", "-q", "wazuh.dashboard", capture=True
        ).strip()
        if existing_dashboard:
            stack("--profile", "dashboard", "stop", "wazuh.dashboard")
    digest = _config_digest(values)
    configs_exist = all(
        (RUNTIME / name).exists()
        for name in (
            "wazuh_manager.conf",
            "filebeat-archives.sh",
            "internal_users.yml",
            "roles.yml",
            "roles_mapping.yml",
        )
    )
    recorded_state = (
        hashlib.sha256(f"{digest}:{_runtime_config_digest()}".encode()).hexdigest()
        if configs_exist
        else ""
    )
    if (
        configs_exist
        and _runtime_configs_valid()
        and INPUT_HASH_FILE.exists()
        and INPUT_HASH_FILE.read_text().strip() == recorded_state
    ):
        healthy, _reason = _stack_healthy(values, dashboard)
        if healthy:
            print(
                f"Wazuh {VERSION} manager and indexer are healthy; "
                "configuration unchanged, reused runtime configs."
            )
            if dashboard:
                print("Dashboard is healthy at https://127.0.0.1:4443")
            return
    was_healthy, _health_reason = _stack_healthy(values, dashboard)
    make_runtime_configs(values)
    stack_args = ("--profile", "dashboard", "up", "-d") if dashboard else ("up", "-d")
    if was_healthy:
        stack_args = (*stack_args, "--force-recreate")
    stack(*stack_args)
    deadline = time.monotonic() + 240
    last_error = "not yet checked"
    while time.monotonic() < deadline:
        healthy, last_error = _stack_healthy(values, dashboard)
        if healthy:
            message = (
                f"Wazuh {VERSION} manager and indexer are healthy; indexer=https://127.0.0.1:9200"
            )
            if dashboard:
                message += "; dashboard=https://127.0.0.1:4443"
            runtime_state = hashlib.sha256(
                f"{digest}:{_runtime_config_digest()}".encode()
            ).hexdigest()
            INPUT_HASH_FILE.write_text(runtime_state + "\n", encoding="ascii")
            print(message)
            return
        time.sleep(4)
    raise RuntimeError(f"Wazuh did not become healthy within 240 seconds: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("prepare", "up", "down", "status"), nargs="?", default="prepare"
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="also start and health-check the optional dashboard",
    )
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            ensure_prerequisites()
            make_runtime_configs(read_env())
            print(f"Prepared Wazuh {VERSION}; run python lab/wazuh/setup.py up")
        elif args.action == "up":
            up(dashboard=args.dashboard)
        elif args.action == "down":
            if UPSTREAM.exists():
                # Include the opt-in dashboard so its container is removed too.
                stack("--profile", "dashboard", "down", "-v")
            subprocess.run(["docker", "network", "rm", "wazuh-lab"], capture_output=True)
        else:
            stack("ps")
        return 0
    except (RuntimeError, subprocess.CalledProcessError, FileNotFoundError) as exc:
        detail = getattr(exc, "stdout", None)
        print(f"Wazuh lab setup failed: {exc}\n{detail or ''}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
