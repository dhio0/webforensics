# webforensics

A defensive tool that reconstructs **how a website was compromised**. It correlates evidence from the webroot (suspicious or modified files, their timestamps and hashes) with web server access logs. Like a human analyst, it starts from the file and traces back to the request that created it and the exploit that made that possible. The final output is an incident report in Indonesian.

> **Status: early development (milestone 4 of 7).** Evidence loading (access + error logs, webroot manifest), detection rules, the file-first correlation engine and the Indonesian report (`webforensics analyze`, Markdown + HTML + JSON) work, tested on two benchmark scenarios. The `eval` command, the full lab benchmark, the Wazuh adapter and vulnerable-line localization are not implemented yet. See [docs/plan.md](docs/plan.md).

## Design principles
- **Deterministic and offline core.** Rules and heuristics only, with no LLM and no network calls in the analysis path. The same inputs always give the same output.
- **Every claim cites evidence.** Each claim points to a log file + line number, or a file path + SHA-256.
- **Honest about uncertainty.** Evidence gaps and confidence levels are explicit, and mtime-only claims are treated as weak because mtime is easy to forge.

## What works today (M4)
```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"   # Windows: .venv\Scripts\pip

# On the compromised server (read-only, needs bash + GNU coreutils):
scripts/collect.sh -w /var/www/html -o /tmp/case01 -l /var/log/nginx

# On the analyst machine: check what was parsed, then analyze.
webforensics inspect --manifest case01/manifest.tsv --log case01/logs
webforensics analyze --manifest case01/manifest.tsv --log case01/logs --out case01/report
```
`analyze` writes `report.md`, `report.html` and `report.json` and prints a short summary:
```
Case WF-A430D528E5: 1 affected file(s), 5 timeline event(s), 1 evidence gap(s)
Root cause (medium): unrestricted_file_upload via POST /admin/upload.php at 2026-10-27T14:16:06+00:00
Attacker IPs: 172.19.0.1
```
The report is in Indonesian and follows a CSIRT incident-handling flow: summary with a short attack story, case info and evidence scope, attack timeline (MITRE ATT&CK, evidence cited per row), root cause with its reasons and alternatives, affected files, changes to review by hand, IOCs, evidence gaps, unrelated attack noise (grouped), recommended actions (containment, eradication, recovery, lessons learned), limitations, and an evidence appendix. Example output for the benchmark scenarios is in [tests/golden/](tests/golden/).

Useful options: `--baseline` (manifest of a known-good webroot), `--error-log` with `--error-log-utc-offset`, `--trusted-proxy` (believe X-Forwarded-For from these), `--display-offset` (report times, default `+07:00` WIB), `--redact-host`, `--format md|html|json`. The same inputs give a byte-identical report, from any working directory, when the report time is fixed with `--generated-at` or `SOURCE_DATE_EPOCH`. File names in the report are relative to the evidence folder, so the analyst's own paths never appear. `report.json` starts with `"format": "webforensics-report/1"` for tools that read it.

The evidence formats are described in [docs/evidence-format.md](docs/evidence-format.md).

## Development
```bash
pytest
ruff check .
```

## Docs
- [docs/plan.md](docs/plan.md): plan, data models, correlation algorithm, milestones, risks
- [docs/decisions.md](docs/decisions.md): design decisions and their reasons
- [docs/evidence-format.md](docs/evidence-format.md): manifest v1 and supported log formats
- [docs/performance.md](docs/performance.md): benchmark numbers and how to reproduce them

## Roadmap
Planned work is listed in [docs/plan.md](docs/plan.md) (§5). A comparison with related tools will be added only after checking those tools first-hand.
