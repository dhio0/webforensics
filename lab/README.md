# Local incident forensics lab

This lab is an intentionally vulnerable teaching application. It binds HTTP only
to `127.0.0.1:8080`; PHP and MySQL communicate on an `internal: true` Docker
network and MySQL has no published port. Nginx also uses a host-access bridge so
Docker Desktop can publish the loopback-only port; do not publish any other
address or port. The PHP product and upload endpoints are intentionally
vulnerable and must remain isolated to this local lab.

The uploaded Scenario A and F files use PHP-like names, but their contents are
only `LAB-FORENSICS-MARKER-v1` and `LAB-FORENSICS-MARKER-F-v1` plain text. They
have no PHP tags or executable behavior. Requests to their PHP-like paths test
static heuristics; PHP-FPM returns the text without executing it. Never run
collected evidence files on the host.

## Requirements

- Docker Desktop or Docker Engine with Compose v2
- Python 3.11+
- This repository installed in the active environment (`pip install -e .`)

## Replay and collect both scenarios

Run each replay from the repository root. Each script first runs
`docker compose down -v`, then rebuilds and starts the stack with
`docker compose up -d --build`. This resets the MySQL and webroot volumes before
each scenario, so evidence from A cannot leak into F or vice versa.

```powershell
.venv\Scripts\python lab/attacks/scenario_a.py
.venv\Scripts\python lab/collect_scenario.py --scenario a

.venv\Scripts\python lab/attacks/scenario_f.py
.venv\Scripts\python lab/collect_scenario.py --scenario f
```

Scenario A makes six fixed requests with two-second pauses: benign browsing, a
GET-SQLi distractor, the unauthenticated upload, and a request to the inert
marker. The upload request is the root cause of the created file; the SQLi probe
is not responsible for it.

Scenario F makes seven fixed requests with two-second pauses: benign browsing, a
failed normal login, a GET-SQLi login bypass, an authenticated upload, and a
request to a separate inert marker. The vulnerable login is the root cause; the
upload endpoint checks the resulting session but does not validate file type.
Both replays use a fixed, scenario-specific User-Agent and reset/reopen nginx's
bind-mounted access log before requests. Timestamps in each captured log are in
the order of the replay and do not share a second.

## Collect and inspect evidence

```powershell
.venv\Scripts\python lab/collect_scenario.py --scenario a
.venv\Scripts\webforensics inspect `
  --manifest benchmark/scenarios/a/evidence/manifest.tsv `
  --log benchmark/scenarios/a/evidence/access.log

.venv\Scripts\webforensics inspect `
  --manifest benchmark/scenarios/f/evidence/manifest.tsv `
  --log benchmark/scenarios/f/evidence/access.log
```

For F, replace `a` with `f` in both evidence paths and the collector option. The
collector runs `scripts/collect.sh` inside the PHP container. Each run saves a
manifest and nginx combined access log in that scenario's `evidence/` folder.
The committed ground truth cites the collected log lines and marker hash. CI
checks every scenario's schema, log citations, file hashes, and distinct step
timestamps without Docker. Collect one scenario before replaying the other,
because each replay resets the shared lab state.

## Stop and remove lab containers

```powershell
docker compose -f lab/docker-compose.yml down -v
```

`-v` removes the lab's MySQL and shared webroot volumes. The evidence under
`benchmark/scenarios/a/evidence/` is a repository artifact and remains in place.

## Safety notes

- Keep Docker port publishing loopback-only (`127.0.0.1`).
- Do not expose this app through a tunnel, proxy, firewall rule, or public host.
- Do not put real files or malware samples in the upload form.
- The replay script is a fixed localhost request sequence, not a general scanner
  or exploitation tool.
- Inspect the collected manifest and log as evidence; never execute or include
  collected files on the host.
