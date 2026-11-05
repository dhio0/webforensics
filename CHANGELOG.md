# Changelog

The decisions behind each change are in [docs/decisions.md](docs/decisions.md) (D-numbers below).

## 0.1.0 — 2026-11-05

The first release.

### What it does

- **File-first reconstruction.** From an access log (nginx or Apache combined, plain or `.gz`), an optional error log and a webroot manifest made by `scripts/collect.sh`, it starts at each suspicious file, picks the most trustworthy write time (btime or ctime before mtime, with a timestomping check), finds the request that wrote it and walks back to the entry point. Scripts used and then deleted are found from the log alone (D85).
- **Detection rules** for SQL injection, path traversal, code and command injection, upload-folder scripts, web shells (request input reaching an exec call, known families by their markers, obfuscation), `.htaccess` handler abuse, defacement pages, online-gambling (judol) spam and search-engine cloaking. Every rule, what it does not prove and the false positives seen: [docs/rules.md](docs/rules.md).
- **Honest confidence.** Each claim cites a log line or a file hash. Evidence gaps, unreadable lines, timestamps that may be forged and logins whose method is not visible lower the confidence and are named. An accused file is labelled by how strongly the evidence says it is the attacker's, and a root cause is never surer than its file (D100).
- **Damaged evidence is said, not hidden.** Out-of-order, cut or mostly unreadable logs, and manifest files the webroot copy cannot give (deleted by an antivirus, locked, a different hash), are reported first when they matter (D96, D101).
- **Vulnerable code.** With the webroot content, it names the PHP line of an SQL injection and shows a prepared-statement fix (D83).
- **Report in Indonesian**, following a CSIRT incident-handling flow (summary, timeline with MITRE ATT&CK, root cause, affected files, IOCs, containment, eradication, recovery, lessons), as Markdown, HTML and JSON, plus an offline viewer (D97). Advice does not take the site down: needed files are restored, not deleted (D99).
- **Wazuh.** Evidence from the Wazuh indexer (web logs and FIM), an integration that starts an analysis on a FIM or web-attack alert, and write-back of the findings as Wazuh alerts ([docs/wazuh.md](docs/wazuh.md)).
- **Deterministic and offline.** No network and no LLM in the analysis; the same evidence gives the same bytes.

### How well it works

Measured against answer keys written before each first run; details in [docs/results.md](docs/results.md).

- Lab benchmark: 5 of 5 scenarios fully correct, through both the file and the Wazuh adapters.
- Benchmark v2 (12 scenarios on real applications attacked with real tools): development 6 of 8, held-out 2 of 4 fully correct; no false accusation.
- Outside cases (Ali Hadi web server and Linux server, BND 2016, BTLO Compromised WordPress, two public-sector servers with 7.6 M log lines): no false accusation remains; the first runs, before any fix, are reported next to the fixed ones.
- Judol spam: 34 of 35 real injected go.id pages found, none of 11 unseen news and research pages about judol flagged.

### Known limits

- Attacks that write nothing (reading files, stealing data) are listed as attack activity but not reconstructed.
- Access logs do not record POST bodies; a login with valid credentials looks like the owner's.
- The code check covers SQL injection in PHP only, within one file and function.
- Calibration of the confidence labels on unseen evidence is not measured yet; the held-out scenarios are kept for the next pre-registered run.
