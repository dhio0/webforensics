# Design decisions

Short ADR-style log. Each entry: decision → reason. Status is "proposed" until the plan is approved.

## D1 — `src/` layout, package `webforensics`, Python 3.11+, hatchling
Status: proposed.
The `src/` layout forces tests to run against the installed package, which catches packaging bugs early. Hatchling is the simplest standard PEP 517 backend and adds no extra tooling.

## D2 — pydantic v2 for data models
Status: proposed.
Evidence is untrusted input, so models need validation (e.g., "a timeline event must have ≥1 citation"). Pydantic also gives free JSON (de)serialization and JSON Schema export for the benchmark ground-truth format.

## D3 — Adapters behind `typing.Protocol` interfaces (`LogSource`, `FileEvidenceSource`)
Status: proposed.
The core only consumes models, so adding Wazuh (or Splunk/Elastic later) means writing one adapter, not touching the correlation logic. Protocols keep this structural and light, with no inheritance tree.

## D4 — Citations are mandatory and enforced in the model
Status: proposed.
The brief requires every timeline row to cite evidence. Enforcing it in a validator makes "unsupported claim" a bug that tests catch, not a review comment.

## D5 — Confidence is categorical (high/medium/low) plus explicit reasons
Status: proposed.
A float like 0.73 implies a precision the heuristics don't have. Categories derived from written rules are explainable in an interview and in a report.

## D6 — All timestamps are tz-aware UTC internally; the report renders in a configurable TZ (default Asia/Jakarta)
Status: proposed.
Logs, file metadata, and Wazuh may use different zones, so mixing naive times silently breaks correlation windows. Display in WIB because the audience is Indonesian.

## D7 — Deterministic core
Status: proposed.
Use stable hash-based IDs, sorted iteration, no wall-clock reads inside the core (`generated_at` is injected), and no randomness. Reproducibility is a brief requirement, and it makes golden-file tests possible.

## D8 — Rules as code + versioned YAML signatures, each with a `rule_id`
Status: proposed.
Every finding can say exactly which rule (and version) fired, which is what an analyst needs to trust or dispute it. Signatures in data files can be updated without code changes.

## D9 — Webroot evidence via a collector script + stat manifest
Status: accepted (Q1).
Copying a folder (zip/scp/Windows) destroys ctime/inode and often mtime, and those are the anchors of file-first correlation. A read-only `collect.sh` captures them on the server at acquisition time.

## D10 — Timestamp trust order: btime/ctime > mtime; mtime-only claims capped at "medium"
Status: proposed.
mtime can be forged with `touch`, while ctime cannot be set from userland. A large mtime/ctime inconsistency is itself reported as a possible timestomp (T1070.006).

## D11 — Root cause = earliest successful exploit on the actor's causal chain; ambiguity yields alternatives, not a guess
Status: proposed.
Forensic reports are judged on not over-claiming. Showing two ranked candidates with reasons is more defensible than one confident wrong answer.

## D12 — Indonesian text lives in a message catalog + Jinja2 templates, never in core logic
Status: proposed.
The core emits language-neutral keys and parameters, so tests don't break on wording changes, and the optional LLM polish layer can work on the rendered text only.

## D13 — No network by default; Wazuh and LLM are explicit opt-ins
Status: proposed.
This is a brief requirement, and it is a sensible default for a forensic tool that may run on sensitive evidence. Any outbound call must be visible in the config.

## D14 — Benchmark: ground truth references log lines and file paths; matching is by citation
Status: proposed.
A predicted step counts as correct if it cites the same log line (or file + hash) as the ground-truth step. That is unambiguous and tool-agnostic, so other tools can use the benchmark too.

## D15 — Treat evidence as hostile
Status: proposed.
Never execute or `include` webroot files. Don't follow symlinks out of the root. Apply size limits on reads. HTML-escape everything in reports (user agents and paths are attacker-controlled → XSS in the report otherwise).

## D16 — Defanged/synthetic malware samples only in the repo
Status: proposed.
Real webshell signatures get quarantined by Windows Defender and can get a GitHub repo flagged. Synthetic samples that trigger the same heuristics test the logic without shipping live malware.

## D17 — Static MITRE ATT&CK table (e.g., T1595, T1190, T1105, T1505.003, T1059.004, T1070.006)
Status: proposed.
A small hand-curated mapping per finding category is deterministic and reviewable. There is no need to pull the full ATT&CK dataset at runtime.

## D18 — Lab-lite (nginx + PHP + MySQL, no Wazuh) in M2, full lab in M5
Status: accepted (Q4).
Rules and correlation built only on hand-written fixtures tend to fail on real nginx output. Generating scenario A early gives realistic evidence from week 2.

## D19 — Baseline is optional; its absence is recorded as an evidence gap
Status: accepted (Q2).
Many small orgs have no clean copy of their site, so the tool must work without one. Saying "no baseline, file status is heuristic" keeps the report honest about how solid the new/modified labels are.

## D20 — Lab ships both GET-based and POST-based SQLi scenarios
Status: accepted (Q3).
Access logs don't record POST bodies, so the POST scenario shows exactly where log-based correlation degrades and how confidence reflects it. Hiding that case would inflate the benchmark.

## D21 — Wazuh: latest stable at install time, exact version recorded in `docs/wazuh-notes.md`
Status: accepted (Q5).
APIs and field names change between versions, so pinning and documenting the tested version (plus the doc pages each detail was verified against) makes the adapter reproducible and its claims checkable.

## D23 — Manifest v1 is TSV with hex-encoded paths
Status: accepted (M1).
File names are attacker-controlled and can contain tabs, newlines or invalid UTF-8. Hex is trivial to produce in bash (`od`) and impossible to break, while JSON would need escaping that plain shell can't do reliably.

## D24 — Bad input lines become `ParseFailure` records, never exceptions
Status: accepted (M1).
One corrupt or malicious line must not hide the rest of the evidence. Failures are counted with a reason, so later they can become evidence gaps ("N lines unparseable").

## D25 — Log format is given explicitly, not auto-detected
Status: accepted (M1).
nginx and Apache "combined" lines look identical, but nginx logs request *end* time and Apache request *start* time. Guessing wrong would silently skew correlation windows.

## D26 — Citations use paths relative to a base dir; local content paths are excluded from output
Status: accepted (M1).
Absolute paths differ per machine and would break determinism and golden tests. `FileEvidence.content_ref` is kept in memory for static analysis but never serialized.

## D27 — `.gitattributes`: LF for `*.sh`, no conversion for evidence fixtures
Status: accepted (M1).
On Windows, git autocrlf would add CRLF that breaks `collect.sh` on Linux and changes fixture hashes and line content, so fixtures must stay byte-identical.

## D22 — Wazuh pull is core; trigger and write-back are stretch goals
Status: accepted.
Reading alerts and FIM events already proves the integration and feeds the same correlation engine. Trigger and write-back add operational polish but cost time the 5–6 week schedule doesn't safely have.

## D28 — File rules read only a bounded content prefix and emit fixed-order findings
Status: accepted (M2).
Static file evidence is untrusted, so content is read only through `content_ref`, as bytes decoded with replacement, and capped at 2 MiB; it is never imported or executed. Rules run in a fixed order for reproducible output, and missing/unreadable content simply disables content-based rules.

## D29 — Obfuscation and changed entrypoint findings stay low confidence
Status: accepted (M2).
High entropy, encoding calls, and changes to `.htaccess` or index files have benign explanations. These signals are useful for triage but are not enough by themselves to claim malicious behavior, so their severity/confidence remain low and entrypoint changes require new/modified baseline status.

## D30 — File execution checks are regex heuristics, not taint analysis
Status: accepted (M2).
Request input stored in a variable and used by a dangerous call in a later statement is not detected; taint tracking is out of scope until M7. PDO-style `->exec(` calls are excluded to avoid treating database execution as command execution.
