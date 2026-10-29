# webforensics

A defensive tool that reconstructs **how a website was compromised**. It correlates evidence from the webroot (suspicious or modified files, their timestamps and hashes) with web server access logs. Like a human analyst, it starts from the file and traces back to the request that created it and the exploit that made that possible. The final output is an incident report in Indonesian.

> **Status: early development (milestone 6 of 7).** Evidence loading (access + error logs, webroot manifest), detection rules, the file-first correlation engine, the Indonesian report (`webforensics analyze`, Markdown + HTML + JSON), the accuracy benchmark (`webforensics eval`, five lab scenarios) and evidence from Wazuh 4.x (`webforensics pull`) work. Vulnerable-line localization is not implemented yet. See [docs/plan.md](docs/plan.md).

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

## Evidence from Wazuh (M6)
If the web server runs a Wazuh 4.x agent with FIM on the webroot, the evidence can come from the Wazuh indexer instead of the server. `pull` is the only command that uses the network. It copies one agent's web log lines and FIM alerts for a time window into a recording, and analysis then runs offline on that file:
```bash
export WF_WAZUH_USER=webforensics_reader WF_WAZUH_PASSWORD=...   # or --password-file
webforensics pull --indexer https://wazuh-indexer:9200 --ca-cert root-ca.pem   --agent web01 --since 2026-10-29T08:00:00+07:00 --docroot /var/www/html   --access-log /var/log/nginx/access.log --error-log /var/log/nginx/error.log --out case01.jsonl
webforensics analyze --wazuh-recording case01.jsonl --out case01/report
```
- Web events come from `wazuh-archives-4.x-*`, because ordinary requests (including a successful upload) never become Wazuh alerts. Archives are off by default in Wazuh; without them, `pull` falls back to alerts and the report marks the log as partial.
- The raw line in `full_log` goes through the same parser as plain log files, so both adapters judge requests the same way. Citations point at lines of the recording (`case01.jsonl:17`).
- Realtime FIM gives the write time (an upper bound, a second or two after the write), so the tool also catches a forged mtime. FIM gives hashes, not file content; `--webroot` adds content, used only where its SHA-256 matches FIM.
- TLS is always verified (`--tls-server-name` when the certificate name differs from the URL host), and the password is never accepted on the command line.

In the lab (Wazuh 4.14.9), all five scenarios were replayed with Wazuh on, and the evidence from that same run was analyzed through both adapters. Root cause, affected files and attacker IPs were identical in every scenario (`tests/integration/test_wazuh_lab.py`, marked `lab`). Building that test exposed two problems: a deploy inside the pull window made every new app file look like an attack (now held to the same standard as lonely writes, D79), and FIM misses a file written while the agent restarts. That blind spot is a limitation of FIM itself; the report states it. Details: [docs/wazuh-notes.md](docs/wazuh-notes.md).

## Accuracy on the benchmark
`webforensics eval benchmark/` runs the analyzer on every lab scenario and compares it with the scenario's ground truth ([docs/evaluation.md](docs/evaluation.md)):

| Scenario | Split | Step recall | Root cause | False IPs | False files | IP precision | File precision | Expected rules | Code line |
|---|---|---|---|---|---|---|---|---|---|
| A: unauthenticated upload | dev | 3/3 | correct | 0 | 0 | 1.00 | 1.00 | - | n/a (M7) |
| B: POST SQLi login bypass, upload | dev | 5/5 | correct | 0 | 0 | 1.00 | 1.00 | - | n/a (M7) |
| D: busy site, no compromise | dev | - | correct (none) | 0 | 0 | - | - | 1/1 | n/a (M7) |
| E: upload + forged mtime | held-out | 3/3 | correct | 0 | 0 | 1.00 | 1.00 | 1/1 | n/a (M7) |
| F: GET SQLi login bypass, upload | dev | 4/4 | correct | 0 | 0 | 1.00 | 1.00 | - | n/a (M7) |

Step recall in B and E includes the PHP error-log line written by the upload, so error-log correlation is measured too. In B the root-cause line is right, but the report does not claim SQL injection: the payload is in the POST body, which access logs don't record. It says the login method is not visible (low confidence) and names SQLi over POST as one possibility.

Read these numbers with care. The benchmark is small, synthetic, and made by the same person who wrote the rules. Scenario D failed on its first run: an admin's photo upload was blamed for a CMS cache file. That was fixed (D69), which counts as tuning on a dev scenario. E is held out and passed on its first run, before that fix. Reading D's report also showed that two bots' SQLi login bypass probably worked; the report now says so and recommends fixing the login, without accusing anyone (D71). Runtime is a few hundredths of a second per scenario (machine-dependent, so the table leaves it out). Large logs are measured in [docs/performance.md](docs/performance.md).

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
- [docs/evaluation.md](docs/evaluation.md): accuracy metrics, splits, and the limits of a self-made benchmark
- [docs/wazuh-notes.md](docs/wazuh-notes.md): Wazuh 4.14 behaviour verified against docs, source and the lab
- [benchmark/README.md](benchmark/README.md): scenario format, and how to score another tool

## Roadmap
Planned work is listed in [docs/plan.md](docs/plan.md) (§5). A comparison with related tools will be added only after checking those tools first-hand.
