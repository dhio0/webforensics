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

## D31 — The lab publishes one loopback port and uses an internal Docker network
Status: accepted (M2).
The app is published only on `127.0.0.1`; PHP and MySQL stay on an `internal: true` network, while nginx also joins a host-access bridge because Docker Desktop does not publish ports from an internal-only network. MySQL has no published port.

## D32 — The uploaded Scenario A artifact is inert plain text with a PHP-like path
Status: accepted (M2).
The marker has a `.php` filename to exercise the extension heuristic, but its bytes contain no PHP tags or behavior. Serving it through PHP-FPM returns the marker text without executing evidence or shipping a functional shell.

## D33 — Scenario A ground truth cites immutable evidence paths and line numbers
Status: accepted (M2).
Each scenario keeps its access log and collector manifest beside its ground truth. CI validates cited log line numbers and file hashes against those artifacts, so later scenarios can reuse the same layout without Docker.

## D30 — File execution checks are regex heuristics, not taint analysis
Status: accepted (M2).
Request input stored in a variable and used by a dangerous call in a later statement is not detected; taint tracking is out of scope until M7. PDO-style `->exec(` calls are excluded to avoid treating database execution as command execution.

## D34 — Scenario A tests "don't blame the distractor"; scenario F tests backtracking
Status: accepted (M2).
In scenario A the upload needs no login, so the upload request itself is the root cause and the earlier SQLi probe is a distractor, which mirrors the constant bot SQLi noise on real sites. Scenario F (SQLi login bypass → upload) is needed so the backtracking step of the correlation algorithm is actually tested.

## D35 — Replay steps are spaced by fixed delays
Status: accepted (M2).
If every request lands in the same second, any time-window correlation "matches" trivially and ordering bugs stay hidden. Fixed delays keep the replay deterministic while giving the evidence a realistic, testable timeline.

## D36 — Every scenario replay starts with empty lab volumes
Status: accepted (M2).
The replay shuts down this Compose project with volume removal before startup, resetting both the MySQL seed state and collected webroot. This prevents a marker or session state from one scenario appearing as evidence in another.

## D37 — Scenario F uses a GET login so the SQLi request is visible in access evidence
Status: accepted (M2).
The lab has no HTTPS or production credentials; GET keeps the intentionally vulnerable authentication bypass visible in the combined log so its ground-truth root-cause request has a precise cited line.

## D38 — Entry point = SQLi on a login endpoint, same client, same URL area
Status: accepted (M3).
Combined logs have no cookies, so "this upload needed that login" is inferred: the same client IP, earlier in time (within `lookback_s`), and the creating request lives under the login endpoint's URL directory (`/admin/login.php` covers `/admin/*`). The earliest successful SQLi-flagged login wins. Because the session link is inferred, this root cause is capped at medium.

## D39 — "No login seen" is absence of evidence, so that root cause is capped at medium
Status: accepted (M3).
When the creating request has no preceding login, it is named the root cause (e.g. unrestricted upload). The event itself can be high confidence, but the root-cause claim stays at most medium: the session may predate the logs. A login with no visible payload (POST body) becomes a LOW `login_method_unknown` entry point instead (valid credentials or an invisible injection; scenario B).

## D40 — Only write-capable requests can be a file's creator; otherwise say "not found"
Status: accepted (M3).
Candidates in `[anchor − 120 s, anchor + 5 s]` must be POST/PUT/PATCH or SQL `INTO OUTFILE`. They are ranked by write semantics, 2xx/3xx, same client as the file's later users, then closeness, then log position. Candidates tied on the first three are kept as LOW alternatives and cap the winner at medium. If there are none, the file event says `creation.no_http_request_found` (SSH/FTP/CI drop, or missing logs) rather than picking a nearby GET.

## D41 — Anchor on btime, then ctime, then mtime; check timestomping only on suspected files
Status: accepted (M3).
`touch` can set mtime but not ctime/btime. If mtime looks forged (older than btime, or older than ctime by > 60 s) and btime exists, the anchor is btime, since the later ctime is probably the `touch` itself. mtime-only anchors cap confidence at medium, and timestamps from a plain copy cap it at low. The forgery check runs only on seed files, because `tar`/`cp -p` deploys also keep old mtimes.

## D42 — A gap lowers an event at most once, and only if it overlaps what the event depends on
Status: accepted (M3).
Each event has a dependency window: the creation window for file and creation events, `[root, anchor + skew]` for an entry point, the request time for context rows. Only time gaps (log silence, parse-error runs, no log coverage) count. Downgrading once avoids a pile of small gaps turning everything into LOW. Every gap lists the event ids it affects.

## D43 — Files identical to the baseline are never treated as suspicious
Status: accepted (M3).
A file whose path and SHA-256 match the known-good baseline was not written by the attacker, even if a rule flags its content (e.g. a vulnerable but original app file). That keeps the vulnerable app code out of the "affected files" list; M7 analyzes it separately.

## D44 — The timeline only covers implicated actors
Status: accepted (M3).
Actors are the clients behind the root cause and creation requests, plus anyone who used a file flagged as a webshell. Their first request, failed logins and attack-flagged requests become context rows. Attack requests from everyone else (bot noise) are not dropped but returned as `unattributed_finding_ids`, so they cannot be mistaken for the incident.

## D45 — Extracted webroot content is re-hashed against the manifest
Status: accepted (M3).
If the extracted bytes don't hash to the manifest's SHA-256, `content_ref` is cleared and a `content_hash_mismatch` failure is recorded. Static analysis then never reasons about a different file version than the one the report cites.

## D46 — The property test is seeded random generation, not a new dependency
Status: accepted (M3).
Sixty seeded random evidence sets check the invariants (no crash, every row cited, sorted, root cause in the timeline, gaps reference real events, identical output on rerun). It is reproducible and keeps the dependency list short; `hypothesis` can replace it later if shrinking is needed.

## D47 — Behind a trusted proxy, the actor is the right-most untrusted X-Forwarded-For hop
Status: accepted (M3).
XFF is only read when `client_ip` is in `trusted_proxies` (IPs or CIDRs, empty by default). The left part of XFF is written by the client and can be forged, so the actor is the first non-proxy hop counting from the right. If the user agent differs between the entry point and the write request, the entry point is lowered one step (`actor.user_agent_changed`): it can be a tool switch or two people behind one IP.

## D48 — A login attempt's outcome is inferred from status, retries and failure fingerprints
Status: accepted (M3).
Failed: 401/403/429; or the same actor retries the same login before loading any non-login, non-static page in that area; or the (path, status, size) equals a failure seen on that endpoint. Otherwise a 2xx/3xx is a success. Only successful logins can be an entry point, so a run of failed "200" logins is not blamed.

## D49 — Weak seeds: lonely code writes need an HTTP link to join the incident
Status: accepted (M3).
Without a baseline or file content, a code file whose trusted write time (btime/ctime, not mtime) sits in a batch of ≤ 2 files (batches = writes ≤ 5 s apart) is a "lonely write". It is traced like a seed, but kept only if a write request or a rarely-hit POST pattern links it to HTTP; the file event is capped at medium. The rest go to `unexplained_changes` for manual review, so an admin's SSH edit is not reported as an attack.

## D50 — Silence gaps use the local request rate
Status: accepted (M3).
The threshold for each interval is max(600 s, 30 × the median of the 25 intervals on each side). A quiet night stays quiet, a missing hour in busy traffic is reported. The trade-off is that a deleted hour in a quiet period is not detected.

## D51 — Error logs corroborate; they decide only when the access log is silent
Status: accepted (M3).
Error-log entries matching an access-log event (same connecting IP, method and path, ± skew) are added as extra citations. If no access-log request could have written a file, an error-log write request in the window becomes the creator at LOW confidence. Error-log unparsed lines (stack traces) are kept apart and never count as missing access-log time. The UTC offset is given by the caller and recorded on every error event.

## D52 — `LogEvent` is a slotted dataclass, not a pydantic model
Status: accepted (M3).
There is one per log line. A pydantic instance carries a `__dict__` and a fields-set, about 1.3 KB of overhead, versus about 80 B for a frozen slotted dataclass. Only our parsers create these, so `__post_init__` checks the few invariants that matter (id present, line ≥ 1, size ≥ 0, timezone-aware time normalized to UTC). Pydantic models (`LogCollection`, the result) still hold them and serialize them. Change one with `dataclasses.replace`.

## D53 — Correlation reads from indexes built once
Status: accepted (M3).
Requests by URL, by actor and by time window are indexed up front, and each step looks up only what it needs. Before, every suspicious file re-scanned the whole log, so a CMS with 50 cache files was 50× slower. `tests/unit/test_performance.py` guards this; numbers are in `docs/performance.md`.

## D54 — The writing request is ranked by closeness to the file's birth first
Status: accepted (M3).
Candidates logged within ±`clock_skew_s` of the anchor come first, then write semantics, success, same actor, distance. Requests answered with 4xx are not candidates (the app refused them). Found with the noisy benchmark: an admin's photo upload 60 s before a CMS cache file was written outranked the comment POST that produced it, and the admin got blamed. If the winner is not upload-like, upload-like requests further away are kept as alternatives.

## D55 — Fetching a webshell URL does not make a client an attacker; using it does
Status: accepted (M3).
Clients who only GET the file (crawlers, curious visitors) stay in the timeline as `file_invoked` but are not implicated actors or IOCs. A POST, or a request flagged by a behaviour rule (e.g. `?cmd=`), is. URL-only rules such as `LOG-WEBSHELL-UPLOAD-DIR` don't count, because they fire for anyone who requests that URL.

## D56 — Code files the app probably generated go to review, not into the incident
Status: accepted (M3).
A seed is set aside (`unexplained_changes`) when it is flagged only by its path, is never requested by URL, was not written by an upload-like request, has no timestomp signal, and its write time is covered by the logs. This is the CMS cache case (`cache/page-1.php` written during a comment POST). Shells with content evidence, or that were used or uploaded, are never set aside. Neither are files whose write time the logs don't cover.

## D57 — Bot payloads don't teach the engine what a failed login looks like
Status: accepted (M3).
Bots replay the same SQLi login payload whether or not it works. Their "retries" were becoming failure fingerprints, and when the bypass response had the same size, the attacker's real bypass was then classed as a failed login (scenario F with noise picked the upload as root cause). Attempts that carry an attack pattern are now excluded from the fingerprints.

## D58 — Report renderers are plain Python with one escape function per format, not Jinja2
Status: accepted (M4).
Jinja2 would be a new dependency for two small templates. Instead, `markdown.py` and `html.py` serialize a fixed set of blocks, and every string passes through `_md` or `_e` (html.escape). Class names and anchors never come from evidence. The HTML has no script and no external resources, and carries a CSP (`default-src 'none'`), so even a missed escape could not run code or call out. Markdown escapes inline markup everywhere, and block markers where text starts a line. IOC code fences grow longer than any backtick run inside them. Tests feed `<script>`, `<img onerror>`, pipes and fake links through user agents, paths and file names.

## D59 — One format-neutral document feeds both renderers
Status: accepted (M4).
`document.py` decides what the report says (sections, tables, lists of plain text). The renderers only decide how it looks. So Markdown and HTML cannot drift apart in content, and the content logic is tested once.

## D60 — Report times are shown in one fixed offset, WIB by default
Status: accepted (M4).
Indonesian readers think in WIB, WITA or WIT. Indonesia has no daylight saving time, so a fixed offset (`--display-offset`) is exact. The zone is printed in the case section and after every time. The JSON keeps UTC.

## D61 — Byte-identical reports: the report time is an input
Status: accepted (M4).
Everything else in the report is derived from the inputs. `generated_at` comes from `--generated-at`, else `SOURCE_DATE_EPOCH`, else the current time. The default case id is derived from the input hashes. Golden files for scenarios A and F are compared byte for byte, and two CLI runs must match them.

## D62 — Unrelated attack noise is grouped per rule
Status: accepted (M4).
A public site gets thousands of bot payloads. Listing them all would bury the incident, but hiding them would hide that the site is a target. The report groups unattributed findings per rule: count, distinct clients, top 5 clients, time range, and one example citation. The summary counts distinct requests, since one line can match several rules.

## D63 — The root-cause row shows both confidences when they differ
Status: accepted (M4).
In scenario A the upload request certainly wrote the file (high). That it was the way in is only medium, because not seeing a login is absence of evidence. The timeline cell reads "tinggi (sebagai titik masuk: sedang)" so the two claims are not confused.

## D64 — Recommendations are deterministic rules over the result
Status: accepted (M4).
They follow the CSIRT phases (containment, eradication, recovery, lessons learned). The fix named depends on the root cause's weakness: upload validation, prepared statements for a SQLi login, or the FILE privilege for SQLi writes. An endpoint that accepted a script behind a login also gets an upload fix. With no root cause, the report says the entry point is unknown and lists what to check, instead of guessing.

## D65 — The report keeps noise as groups, not as one record per request
Status: accepted (M4).
`report.json` first copied every unattributed finding with its log excerpt: 23 MB for a 200k-line log where 1 in 8 lines is a bot payload. The report now drops unattributed log findings after grouping them (D62), which brought that run to 16 KB. Findings on files are kept, because they feed the review section and are few. The full per-request list is still available from the correlation API.

## D66 — Names in the report are relative to the evidence folder, not the working directory
Status: accepted (M4).
Input names were relative to the current directory. So the same evidence gave a different report (and case id) depending on where `analyze` ran, and evidence outside that directory showed absolute paths such as `C:/Users/<analyst>/...`. Names are now relative to the deepest folder that holds all inputs (`case01/logs/access.log` and `case01/manifest.tsv` give `logs/access.log` and `manifest.tsv`). A test runs the CLI from two directories and checks that the bytes match and contain no local path.

## D67 — The report states its scope, tells the story, and shows the payload
Status: accepted (M4).
- **Scope:** the case section lists the log period, lines read and unreadable, error-log entries, files in the manifest, collection time, and whether a baseline was used. A CSIRT report must say what was examined, not only what was concluded.
- **Story:** the summary lists only the incident's main steps (entry point, write, file, first use by the attacker) for non-technical readers. Recon, failed logins and alternatives stay in the full timeline.
- **Payload:** the root-cause section shows the raw log line, because the SQLi payload sits in the query string, which the event text leaves out.
- **Format version:** `report.json` carries `format` so the M5 evaluator and later Wazuh tooling can detect changes.

## D68 — The evaluator scores by log line and counts false accusations
Status: accepted (M5).
A step or root cause matches by the (log file, line number) a timeline event cites, which is exact and needs no text matching. A root cause found only among the alternatives is not counted as correct, because the report did not commit to it. Precision counts reported attacker IPs and affected files that are not in the ground truth, since blaming an innocent client or file is the costly mistake. Held-out scenarios are summarized separately and are never used to tune rules. The evaluator's own tests feed it ground truth that disagrees with the analysis, so it is shown to catch each kind of error.

## D69 — A request already explained by another file ranks after one that nothing explains
Status: accepted (M5).
Found by scenario D (dev) on its first evaluation. An admin's photo upload and a comment POST were logged 2 s apart, both within ±`clock_skew_s` of a CMS cache file's birth. Inside that window, write semantics won, so the upload was named as the cache file's writer and the admin was blamed (a false root and two false accusations). Now a candidate whose time is strictly closer to another file's birth (the photo, born in the upload's own second) ranks after candidates that nothing else explains. It changes the order only: if the photo is missing from the evidence, the upload still wins. Files born in the same second as each other (one request writing a shell and a thumbnail) do not demote each other. Held-out E had already passed before this change and was not used for it. Risk: if an attacker's shell is born a few seconds away from its own upload while another file is born right at that upload's second, a benign request could win. The upload then still shows as an alternative candidate, since upload-like requests are kept as alternatives when the winner is not upload-like.

## D70 — Background noise counts clients the way the engine does
Status: accepted (M5).
The "other attack activity" table counted the raw connection address. Behind a trusted proxy (scenario D's edge), every bot showed up as the proxy, as one client. The report builder now resolves clients through X-Forwarded-For with the same `--trusted-proxy` rule as the engine.

## D71 — A bypass that looks successful is reported even when nothing was compromised
Status: accepted (M5).
Found by reading scenario D's report. Two bots sent the SQLi login bypass and got the same response as the admin's real login, so they probably got in, but uploaded nothing. The engine already inferred these logins as successful, yet the report only listed them as bot noise. Now an SQLi login attempt that looks successful and is not part of the incident timeline gets the finding `CORR-SQLI-LOGIN-BYPASS` (medium confidence, inferred from the response). The report says so in the summary, recommends fixing the login query and ending active sessions, and still accuses nobody: no IOC, no root cause. The attacker's own bypass in an incident (scenario F) is already the root cause and does not get it twice. The outcome comes from the existing login rules, so an attempt followed by a retry from the same client still counts as failed.

## D72 — No "find the entry point" advice when nothing was compromised
Status: accepted (M5).
With no compromise, the report used to recommend checking "the endpoints in the timeline" for an entry point, but the timeline is empty. That advice now only appears when files were affected. The caution stays in the summary ("does not guarantee the server is clean") and in the review of unexplained changes.

## D73 — Wazuh 4.14.x only, read through explicit `-4.x-` index names
Status: accepted (M6).
The lab installs the latest 4.14 patch on install day (D21). Wazuh 5.0 replaces the alert and archive indices (`wazuh-events-v5-*`, `wazuh-findings-v5-*`), and the indexer's `GET /` reports the OpenSearch version, not the Wazuh one. So the adapter queries `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*` explicitly, the names the official 4.x index template covers. On 5.x the indices don't exist and the adapter stops with a clear error instead of returning an empty result. Details and sources: `docs/wazuh-notes.md` §1.

## D74 — Web events come from `wazuh-archives-*`; alerts-only is a degraded mode
Status: accepted (M6).
In the 4.14.9 web rules, ordinary 2xx/3xx requests are level 0 and alerts start at level 3, so the upload POST, webshell POSTs and POST-body SQLi never reach `wazuh-alerts-*`. Those are exactly the requests file-first correlation needs. Archives hold every event but are off by default (`logall_json` + Filebeat `archives`). The lab enables them. Without them the adapter still runs on alerts, but adds one `wazuh.alerts_only` evidence gap, turns the log-silence detector off (it would fire almost everywhere), and lowers confidence. Notes §3.1.

## D75 — Re-parse `full_log` with our own parser; Wazuh rule verdicts are not scored
Status: accepted (M6).
Wazuh's access-log decoders extract only source IP, method, URL and status: no request time, user agent or X-Forwarded-For, and `srcip` names the proxy behind our edge. Every archive and alert event carries the raw line in `full_log`, so the adapter feeds it to the same parser as the FileAdapter. The request time comes from the log line, not from Wazuh's `timestamp` (manager processing time). Wazuh's `rule.id` is shown to the analyst in the citation but does not affect findings, so both adapters judge evidence the same way. Notes §3.2–3.3.

## D76 — FIM time is a first-class timestamp in the core
Status: accepted (M6).
Wazuh FIM gives no ctime or btime, only mtime and the alert's manager-side `timestamp`. Pretending that time is a btime or ctime would overclaim.
- `FileEvidence` gets `fim_first_seen`, `fim_last_seen` and `fim_mode`.
- `choose_anchor` gets a FIM branch. With realtime or whodata FIM, the first `added` time is the anchor, capped at medium confidence: it is an upper bound and compares the manager clock with the web server clock. With scheduled FIM (default every 12 h), the mtime is the anchor, capped at low, and the FIM time only bounds the window.
- `lonely_writes` accepts realtime FIM anchors.
- `syscheck.mtime_after` is formatted in the manager's local time with its offset cut off (a 20-byte `strftime` buffer in `to_json.c`), and the indexer reads it as UTC. So the adapter reads `_source`, never the indexer's `fields`, and applies the offset of the same alert's `timestamp`.
Notes §4.

## D77 — File content only from a hash-matched `--webroot`
Status: accepted (M6).
FIM provides hashes and metadata, not bytes, so the content rules (D28) and M7's code localization have nothing to read. A FIM `added` event still makes a new code file a strong seed, so root-cause tracing works without content. Content can be supplied with an optional `--webroot` snapshot. A file's content is used only if its SHA-256 equals the FIM `sha256_after`; otherwise it is ignored and the mismatch is reported. Without a snapshot, the report says content analysis was not performed.

## D78 — Pull to a recording, analyze offline; deleted files keep their last hash
Status: accepted (M6).
`pull` is the only step that touches the network. It writes the raw hits (`_index`, `_id`, `_source`, unaltered) plus a header (Wazuh version, indices, time window, agent, query, pull time, archives present) to a JSONL recording. `analyze` reads the recording offline. Rerunning on the same recording gives byte-identical output, CI and the benchmark need no Wazuh, and the recording's SHA-256 in the report makes it an evidence copy. Paging uses PIT + `search_after` sorted by `timestamp` then `_id`, as the OpenSearch 2.19 docs recommend. The agent builds `deleted` events from its stored entry, so they carry the last `sha256_after`; a deleted file becomes `FileEvidence` with a `deleted` flag, or a finding citing the alert if no hash is present. Credentials come from the environment or a file, TLS is verified against the lab CA, and the lab uses a read-only indexer user.

## D79 — A file written in a deploy batch needs an HTTP write to be accused
Status: accepted (M6).
Found in the live lab: the PHP container copied the app into the webroot right after the Wazuh agent's baseline scan, so FIM reported ten files as `added` within 0.1 s, and all eight code files were reported as affected. A legitimate deploy inside the pull window looks the same. So a code file whose only signals are being new or changed (the status itself, or rules that fire only on status, such as an index file change) and whose trusted write time sits in a batch of more than `lonely_cluster_max` files (the batches of D49) is traced like a weak seed. It joins the incident only if a request plausibly wrote it. A rarely-hit POST to it is not enough: an upload form used once by an admin looks like that too. Otherwise it is listed under changes to review. Files with content or path findings (a script in `uploads/`) are unaffected. The FileAdapter benchmark gave the same results before and after. Trade-off: a webshell planted by a non-HTTP batch write (a compromised deploy pipeline) without content findings is listed for review instead of accused.

## D80 — WazuhAdapter details settled while building it
Status: accepted (M6). Refines D75–D78.
- **Citations point at the recording.** Wazuh does not keep the line number of the original log, so a web event is cited as `<recording>:<JSONL line>`, and that line holds the raw log line in `full_log`. FIM alerts are cited the same way. This replaces "the report says the line number is not available" (notes §7.7).
- **Header without a Wazuh version.** The indexer's `GET /` reports the OpenSearch version and needs a cluster permission the read-only user does not have. The header records the index patterns actually read (`-4.x-`), which is what identifies the schema (D73).
- **What each FIM path becomes.** A path with at least one add or change becomes one FileEvidence with every alert as a citation. Its hash is the last one seen, the anchor is the alert for the write that produced that hash, and status is new if the first alert is `added`, else modified. A path that was only deleted goes to `deleted_paths`. A path outside `--docroot` becomes a low-confidence finding to review. A path without any hash is counted as unreadable, since nothing identifies its content.
- **FIM is the baseline.** `FileCollection.has_baseline` suppresses the "no baseline" gap, and files FIM did not report (unchanged) are not in the evidence at all; the report says "files changed according to Wazuh FIM".
- **Deletion and timestomp.** A deleted implicated file gets its own timeline event (T1070.004). With realtime FIM, an mtime more than `timestomp_min_s` older than the alert for that content is a timestomp signal; scenario E is caught this way in the lab.
- **Blind spot, stated in every Wazuh report.** FIM sees only changes while the agent runs. In the lab, a file written during an agent restart joined the new baseline without an alert. The lab agent now sets `<auto_restart>no</auto_restart>` (it uses no centralized config), and `limit.fim_blind_spots` is added to Wazuh reports.

## D81 — An error-log client that is a trusted proxy is not an actor
Status: accepted (M6). Fixes a bug from M5.
Error logs have no X-Forwarded-For. When a file's writer is found only in the error log (no access-log line, e.g. Wazuh without archives), its client IP was taken as the attacker. Behind a reverse proxy that IP is the proxy itself, so the report told the admin to block their own proxy. Found by pulling scenario E from the lab in alerts-only mode. Now a trusted-proxy client leaves the actor unknown, the event says why (`error_log.client_is_proxy`), and no IP is accused.

## D82 — Extend the plan: realistic benchmark (M8) and wider coverage (M9)
Status: accepted (2026-10-29, after M6).
The five lab scenarios are small, synthetic, and written by the rule author, so perfect scores there prove little about real incidents. Order: M7 first (the pitch's unmet promise), then M8, then M9.
- **Independent ground truth where possible.** M7 adds fixtures from SQLi CVEs in open-source PHP projects; the lines changed by the upstream fix commit are the answer key. M8 adds scenarios attacked blind by third parties.
- **Realism from real sources, not invented data.** Real vulnerable applications, real attack tools (sqlmap, Weevely, commix), real public access-log traffic as background. All attacks stay inside the isolated lab; webshell samples stay defanged or inert in the repository.
- **No uncensored LLM for benchmark data.** Suggested: an "abliterated" model. Rejected: LLM-invented scenarios are still synthetic and self-made, which is the problem being fixed; real tools already produce real traffic; and an unverifiable, refusal-stripped hosted model is a poor fit for a blue-team project and for evidence privacy. Mainstream assistants may still help write scenario scripts and noise generators.
- **Hard limits stay stated.** A root-level attacker can forge timestamps and logs, and POST bodies are not in access logs unless another source (ModSecurity, application logs) is given. M9 narrows both (Wazuh-vs-server log comparison, optional ModSecurity evidence) but the report keeps saying what cannot be proven.
- **UI deferred.**

## D83 — SQL injection localization: tree-sitter taint tracking, judged on real CVE fixes
Status: accepted (M7).
- **Parser:** tree-sitter with tree-sitter-php (both MIT, prebuilt wheels, no compiler). Risk #10 is closed; no regex fallback was needed.
- **Analysis:** taint tracking per scope (file top level, each function, method and closure). Sources are request superglobals and a few request functions. Taint flows through assignment, arrays, concatenation, interpolation, `.=`, `??`, ternaries and string helpers; any other function's result is clean (calls are not followed). Int/float casts, `intval`-style functions, hashes and early-exit guards (`if (!is_numeric($x)) exit;`, `in_array` whitelists) clean a value. Escaping protects only inside quotes. Exclusive paths (`if`/`else`, `switch` cases, `try`/`catch`) start from the same state and merge afterwards; a loop merges with the state before it, and a loop that rewrites every element of an array replaces its taint.
- **Sinks:** the driver functions and methods (`mysqli_query`, `->query`, `->prepare`, ...), plus any call that receives a tainted string which is plainly an SQL statement, minus hashing, logging, caching and string/array helpers. Real applications wrap the driver (`dbFetchRow`, `sqlDAL::readSql`); without this rule 3 of the detected CVEs were missed.
- **Reported line:** where the input enters the query string; the line that runs the query is shown next to it. The fix is a prepared statement for the API in use (PDO, mysqli procedural or OO, `pg_query_params`, `$wpdb->prepare`).
- **What is analyzed:** only the implicated endpoints (root cause, its alternatives, writer requests), with content hash-checked against the evidence, or from `--webroot` marked unverified (confidence capped at medium).
- **Real-code evaluation:** every reviewed GitHub advisory for Composer packages with CWE-89 and a fix commit, filtered by a rule fixed before scoring: one PHP file changed outside tests, and the vulnerable file reads `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`. 13 of 175 commits passed; most real PHP SQLi lives in frameworks, ORMs and request objects, outside the brief's scope. Code is stored only for MIT projects; the rest is fetched by a script into an ignored cache.
- **Metric, chosen after seeing the first result:** the first scoring counted a hit only when the reported line was one the fix changed, and found 0/13. Reading the cases showed fixes often change the line that reads or cleans the input, while the tool reports where the input enters the query (TorrentPier: the fix casts `$forum_id` at line 76; the tool flagged the query at line 364, and that finding disappears with the fix). So "detected" now means: a finding in the vulnerable file that the upstream fix removes. The stricter "exact line" is still reported. This change is disclosed in docs/evaluation.md.
- **Result:** 5/13 detected, 2/13 on the exact line, and no finding in any of the 13 fixed files. The 8 misses are out of scope by category (calls or object properties: 3, framework or application input APIs: 4, an advisory that is not SQL injection: 1). Hand-made fixtures: 12 positive and 10 negative all correct, one documented limitation (a value returned by a helper function).
