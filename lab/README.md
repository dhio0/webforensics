# Local incident forensics lab

This lab is an intentionally vulnerable teaching application. It binds HTTP only
to `127.0.0.1:8080`; PHP and MySQL communicate on an `internal: true` Docker
network and MySQL has no published port. Nginx also uses a host-access bridge so
Docker Desktop can publish the loopback-only port; do not publish any other
address or port. The PHP product and upload endpoints are intentionally
vulnerable and must remain isolated to this local lab.

The uploaded Scenario A file is `lab-marker.php`, but its content is only the
plain text `LAB-FORENSICS-MARKER-v1`. It has no PHP tags or executable behavior.
The request to its PHP-like path tests static heuristics; PHP-FPM returns that
text without executing it. Never run collected evidence files on the host.

## Requirements

- Docker Desktop or Docker Engine with Compose v2
- Python 3.11+
- This repository installed in the active environment (`pip install -e .`)

## Start and replay Scenario A

From the repository root:

```powershell
docker compose -f lab/docker-compose.yml up -d --build
.venv\Scripts\python lab/attacks/scenario_a.py
```

The replay makes six fixed requests in order, all to `127.0.0.1`: benign catalog
browsing, a GET SQL injection that returns seeded rows, a minimal upload form
submission containing the inert marker, and a GET of that marker. It uses one
fixed User-Agent. The script clears and reopens the bind-mounted nginx access log
before replay so its line numbers are repeatable. The PHP source and database are
teaching fixtures, not copies of a real application.

## Collect and inspect evidence

```powershell
.venv\Scripts\python lab/collect_scenario.py
.venv\Scripts\webforensics inspect `
  --manifest benchmark/scenarios/a/evidence/manifest.tsv `
  --log benchmark/scenarios/a/evidence/access.log
```

The collector runs `scripts/collect.sh` inside the PHP container. It saves the
manifest and nginx combined access log under
`benchmark/scenarios/a/evidence/`. The committed `ground_truth.json` cites the
collected log lines and marker hash. CI checks those citations without Docker.
If you intentionally change the replay, regenerate evidence and update the
ground truth only after verifying every line number and hash.

## Stop and remove lab containers

```powershell
docker compose -f lab/docker-compose.yml down -v
```

`-v` removes the lab's MySQL and upload volumes. The evidence under
`benchmark/scenarios/a/evidence/` is a repository artifact and remains in place.

## Safety notes

- Keep Docker port publishing loopback-only (`127.0.0.1`).
- Do not expose this app through a tunnel, proxy, firewall rule, or public host.
- Do not put real files or malware samples in the upload form.
- The replay script is a fixed localhost request sequence, not a general scanner
  or exploitation tool.
- Inspect the collected manifest and log as evidence; never execute or include
  collected files on the host.
