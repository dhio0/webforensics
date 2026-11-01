# Local incident forensics lab

This lab is an intentionally vulnerable teaching application. Direct nginx
binds only to `127.0.0.1:8080`; the edge proxy binds only to
`127.0.0.1:8081`. PHP and MySQL communicate on an `internal: true` Docker
network and MySQL has no published port. Nginx and the edge use a fixed-subnet
host-access bridge; do not publish any other address or port. The vulnerable
PHP endpoints must remain isolated to this local lab.

Uploaded markers in A, B, E and F use PHP-like names, but contain only inert
`LAB-FORENSICS-MARKER-...` plain text with no PHP tags or executable behavior.
PHP-FPM returns the text without executing it. Scenario D's upload is a tiny
valid PNG. Its comment cache writer creates static HTML in a `.php` file, with
no PHP tags. Never run collected evidence files on the host.

## Proxy simulation

Scenarios B, D and E send every HTTP request through the edge on port 8081. The
edge forwards to nginx at fixed address `172.30.0.2` on the
`172.30.0.0/24` host-access subnet; the edge address is `172.30.0.3`. It sets
`X-Forwarded-For` from the lab-only `X-Lab-Client-IP` request header when
present and otherwise uses the edge's remote address. The header simulates
client addresses for the scripted lab requests and exists only on the
loopback-only edge. It is not enabled on the direct nginx listener. Nginx logs
its actual peer address and the forwarded address as the quoted final field.
Direct requests to port 8080 have `"-"` in that field.

## Requirements

- Docker Desktop or Docker Engine with Compose v2
- Python 3.11+
- This repository installed in the active environment (`pip install -e .`)

## Replay and collect

Run each replay from the repository root. Each script first runs
`docker compose down -v`, rebuilds and starts the stack, waits for MySQL to
accept PHP connections, and resets the nginx logs. This resets the database and
webroot volumes before each scenario.

```powershell
.venv\Scripts\python lab/attacks/scenario_a.py
.venv\Scripts\python lab/collect_scenario.py --scenario a

.venv\Scripts\python lab/attacks/scenario_f.py
.venv\Scripts\python lab/collect_scenario.py --scenario f

.venv\Scripts\python lab/attacks/scenario_b.py
.venv\Scripts\python lab/collect_scenario.py --scenario b

.venv\Scripts\python lab/attacks/scenario_d.py
.venv\Scripts\python lab/collect_scenario.py --scenario d

.venv\Scripts\python lab/attacks/scenario_e.py
.venv\Scripts\python lab/collect_scenario.py --scenario e
```

Scenario A makes six fixed requests: benign browsing, a GET-SQLi distractor,
the unauthenticated upload and a request to its inert marker. The upload is the
root cause. Scenario F makes seven requests including a failed login, GET-SQLi
login bypass, authenticated upload and marker request. The bypass is its root
cause. Scenario B is the same authentication chain with a POST-body bypass,
preceded by a failed POST login and two benign clients. Its bypass is the root
cause. B and E pause two seconds between requests so their log timestamps do
not share a second.

Scenario D collects a pristine baseline, then sends ten ordinary page requests,
six fixed SQLi/login probes from two bot clients, a normal administrator login
and valid PNG upload, a visitor comment that writes `cache/page-1.php`, and
three crawler requests. Nothing is compromised. Probe, upload and comment
steps are excluded from the expected timeline to measure false accusations.
Background requests may share a second.

Scenario E collects a pristine baseline, sends three benign requests, uploads
and requests an inert marker without authentication, then simulates a timestamp
change with `docker compose exec php touch` outside HTTP. The marker cannot
perform this step through the web application. Two benign requests follow.
Its ground truth records the marker mtime, ctime and btime values.

Use `--baseline-only` only after starting a fresh lab and before sending
traffic; the D/E replay scripts do this automatically. Normal collection saves
`manifest.tsv`, `access.log`, and `error.log` when present. D and E also save
`baseline.tsv`. Nginx and PHP containers run in UTC; ground truth records the
error-log offset as `+0000`. PHP's `fastcgi.logging = 1` setting sends
`error_log()` messages over FastCGI, so nginx records them in `error.log` with
the `FastCGI sent in stderr` prefix and the associated client and request.

## Re-recording a scenario

Scenarios B, D and E may be re-recorded when their replay or lab behavior
changes. Do not re-record A or F: golden reports and noisy-variant tests depend
on their exact evidence bytes, and a re-run would add the forwarded-address
field and an nginx error log. After any re-run, rewrite that scenario's
`ground_truth.json` from the replay and collected evidence, never from analyzer
output. Maintainers should then regenerate golden reports with
`UPDATE_GOLDEN=1 pytest tests/integration`, review the diff, and run
`webforensics eval benchmark/` to update the README results table.

Inspect evidence without running it:

```powershell
.venv\Scripts\webforensics inspect `
  --manifest benchmark/scenarios/d/evidence/manifest.tsv `
  --log benchmark/scenarios/d/evidence/access.log
```

Collect one scenario before replaying another, because each replay resets the
shared lab state. CI checks the ground-truth schema, cited log lines, file
hashes and relevant step timestamps without Docker.

## Stop and remove lab containers

```powershell
docker compose -f lab/docker-compose.yml --profile wazuh down -v
```

`-v` removes the lab's MySQL and shared webroot volumes. Collected evidence in
`benchmark/scenarios/` remains in the repository.

## Wazuh mode

Wazuh evidence collection is optional. The regular replays retain their existing
behavior unless `WF_LAB_WAZUH=1` is set. Wazuh mode uses the stable version
recorded in `lab/wazuh/VERSION` (currently `v4.14.9`) and a separate Docker
network named `wazuh-lab`. It publishes only the indexer at `127.0.0.1:9200`
(plus the dashboard at `127.0.0.1:4443` when started with `--dashboard`);
manager ports stay inside Docker. The lab
agent joins only `wazuh-lab`, reads the webroot and nginx logs through read-only
mounts, and does not join the application network.

Prepare and start the manager stack once. The dashboard is disabled by default
to keep memory use down; add `--dashboard` only when it is needed. The generated manager config turns off modules the lab does not use:
vulnerability detection (its CVE feed alone takes about 13 GB of disk),
syscollector, SCA, rootcheck and the manager's own syscheck. The agent's FIM
and log collection are unaffected. Wazuh containers do not auto-restart with
Docker Desktop; start them with `setup.py up` when needed. The indexer
heap remains at the upstream default. `setup.py` checks `vm.max_map_count`
inside the Docker VM (at least 262144), checks out the pinned `wazuh-docker` tag
under ignored `.upstream/`, generates certificates there, and creates random
lab-only credentials in the ignored `lab/wazuh/.env`. The committed
`.env.example` lists the supported keys. Runtime user hashes and derived
configuration stay under ignored `.runtime/`.

```powershell
.venv\Scripts\python lab/wazuh/setup.py up
$env:WF_LAB_WAZUH = "1"
.venv\Scripts\python lab/attacks/scenario_a.py
.venv\Scripts\python lab/attacks/scenario_a.py  # Repeat once to verify re-enrollment.
.venv\Scripts\python lab/collect_scenario.py --scenario a
.venv\Scripts\python lab/wazuh/smoke_check.py  # Run last; it deletes the inert marker.
```

Run any other fixed replay the same way while `WF_LAB_WAZUH` is set. Before
each replay, the manager is checked, the lab is reset with `down -v`, the nginx
logs are truncated, and only then is the profiled agent started. The replay
waits for the agent's first FIM scan and for logcollector to open both log
files. After the final request, it waits for that access-log line to appear in
`wazuh-archives-4.x-*`, then compares a SHA-256 listing of the webroot taken
before and after the replay and waits until every added, modified or deleted
path has a `syscheck` alert from this replay in `wazuh-alerts-4.x-*`. The agent uses a fixed name; the manager's documented
`<auth><force>` replacement settings allow re-enrollment after each lab volume
reset. Each re-enrollment gets a new agent ID (001, 002, ...), and alerts from
earlier replays stay indexed, so queries filter by agent name and time window.

The smoke check is intended for Scenario A and uses the read-only
`webforensics_reader` account with the generated root CA. It prints the open
checks in `docs/wazuh-notes.md` §10 and additional checks for archive line
content, event timing, read-only writes, PIT pagination, and container RAM. Its
marker deletion is a lab-only operation after the replay, not part of Scenario
A's ground truth. Capture `docker stats --no-stream` with the Wazuh stack idle,
during Scenario A with the lab containers running, and after the run. Keep the
indexer heap at the upstream default and report its `OPENSEARCH_JAVA_OPTS`.

Stop both stacks and remove their volumes after use:

```powershell
docker compose -f lab/docker-compose.yml --profile wazuh down -v
.venv\Scripts\python lab/wazuh/setup.py down
```

Without `WF_LAB_WAZUH=1`, run the existing replay commands above as before.

## Safety notes

- Keep all Docker port publishing loopback-only (`127.0.0.1`).
- Keep MySQL and PHP on the internal Docker network. The host-access bridge is
  only for nginx and the loopback edge proxy.
- The `X-Lab-Client-IP` simulation header exists only on the loopback edge;
  never expose that edge outside localhost.
- Do not expose this app through a tunnel, proxy, firewall rule, or public host.
- Do not put real files or malware samples in the upload form.
- Replays are fixed localhost request sequences, not general scanners.
- Inspect collected manifests and logs as evidence; never execute collected
  files on the host.
