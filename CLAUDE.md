# Project brief: web incident forensics tool (portfolio project for a blue-team internship)

## Who I am / context
I'm a 5th-semester Computer Science student targeting blue team / SOC internships. I'm comfortable with Python and have authored web-exploitation CTF challenges (eval bypass, unrestricted file upload), so I understand how these attacks look in logs. This project is the defensive centerpiece of my portfolio. Explain design decisions briefly as you go; replies to me can be in casual Indonesian or English.

## One-line pitch
A defensive tool that reconstructs how a website was compromised by correlating evidence from files on the server (webroot) with web server logs (optionally pulled from Wazuh), points to the vulnerable line of code, and produces an actionable incident report in Indonesian.

## Problem
When a small organization's site (e.g., a university or SME) gets hacked, admins ask: "How did they get in, when, what did they change, is it clean?" Today the answer is found manually: find a webshell in the webroot, check its modification time, then dig through access logs from that timestamp backwards. Indonesian CSIRT guides describe exactly this manual flow. I want to automate it.

## Core pipeline
1. Collect evidence: web access/error logs (nginx combined, Apache) + a snapshot of the webroot (or Wazuh FIM/syscheck events + web logs from Wazuh).
2. Correlate, starting from files like a human analyst: suspicious/new/modified file -> its timestamps and hash -> the request(s) that created or invoked it -> the originating exploit request (root cause).
3. Build an attack timeline with MITRE ATT&CK mapping. Every timeline row must cite its evidence (log file + line number, or file path + SHA-256).
4. Explicitly state evidence gaps (e.g., "no log between 10:07 and 10:40; conclusions may be incomplete") and confidence levels. Note that mtime can be forged (timestomping): use ctime/inode info and hashes where available and lower confidence when only mtime supports a claim.
5. Static analysis of the implicated source file to locate the vulnerable code. Scope for MVP: SQL injection in PHP (user input from $_GET/$_POST/$_REQUEST concatenated into a query string). Show the vulnerable line and a prepared-statement fix. Report confidence honestly; do not over-claim.
6. Generate a report (Markdown + HTML) in Indonesian, structured like a CSIRT incident-handling flow: summary, timeline, root cause, affected files, IOCs, recommended actions.
7. Optionally write conclusions back to Wazuh.

## Architecture requirements
- Python 3.11+, CLI with Typer, type hints, ruff, pytest, packaged with pyproject.toml.
- Core engine is fully offline and DETERMINISTIC (rules/heuristics, no LLM in the core path). Results must be explainable and reproducible.
- Adapter pattern: the core only talks to interfaces such as `LogSource` and `FileEvidenceSource`. Implement a `FileAdapter` (plain log files + webroot folder) first, then a `WazuhAdapter`. Leave room for Splunk/Elastic adapters later (roadmap only).
- WazuhAdapter: pull alerts from the Wazuh Indexer (OpenSearch-based, wazuh-alerts-* indices) and read syscheck (FIM) events for file evidence; support an optional trigger (a Wazuh integration/active-response script invokes the tool when a web-attack or webroot-FIM alert fires) and writing findings back as events picked up by custom decoders/rules. IMPORTANT: verify these details against the current official Wazuh documentation before implementing; don't assume.
- Optional LLM layer (off by default, behind config): only for polishing report wording or explaining the vulnerable code; must support local models and redact IPs/hostnames before sending anything out.
- No network calls by default. No scanning of any third-party systems. The tool analyzes evidence it is given.

## Detection heuristics to start with (log + file)
- Successful exploitation indicators: attack-pattern requests (SQLi, path traversal, upload) that returned 2xx and are followed by new/changed files or new endpoints.
- Webshell indicators: files in upload/writable dirs with executable extensions, dangerous functions fed by request variables (eval, system, shell_exec, base64_decode + request input), known webshell signatures, high-entropy/obfuscated content, POST requests to rarely-hit files.
- Persistence indicators: unexpected new files in odd places, modified .htaccess/index files, hidden dirs, cron/service changes if evidence is provided.

## Evaluation (this is a key differentiator, build it early)
- Docker Compose lab: an intentionally vulnerable PHP demo app (SQL injection + unrestricted file upload), nginx, and a single-node Wazuh. Isolated network only. Attack steps are minimal scripted request replays whose sole purpose is to generate evidence with known ground truth.
- Each scenario ships a ground-truth JSON (ordered attack steps, root-cause request, created/modified files).
- Metrics: step recall, precision (false accusations), root-cause correctness, vulnerable-line localization accuracy, runtime. Output a results table for the README.
- Package the scenarios as an open benchmark folder so others can test their own tools.

## Honest positioning (do NOT claim novelty falsely)
Similar tools exist: Cyber Incident Storyteller (ais), WebLogForensics, LORG, ShadowPulse. As far as I found, they work from logs OR collect host artifacts but don't correlate webroot file evidence with logs starting from the file, don't localize the vulnerable code, and don't publish accuracy against ground truth. Before the README makes any comparison claims, check those repos yourself and word the comparison conservatively.

## Priorities
MVP: FileAdapter + file<->log correlation + timeline + Indonesian report + lab + evaluation.
Next: WazuhAdapter (pull, trigger, write-back) + SQLi code localization.
Roadmap (README only): unrestricted-upload code localization, auto-generated prevention rules (Sigma / ModSecurity), "is it clean now?" re-scan, Splunk/Elastic adapters.
Timeline target: roughly 5-6 weeks. Commit per milestone.

## How I want you to work
1. First, don't write code. Read this brief, ask me any clarifying questions (max 5), then propose a repo structure, data models (evidence, finding, timeline event), and a milestone plan.
2. After I approve, scaffold the project and implement milestone 1 with tests.
3. Keep README, docs, and the benchmark updated as you go. Keep functions small and testable.
4. Flag risks and shortcuts honestly instead of hiding them.