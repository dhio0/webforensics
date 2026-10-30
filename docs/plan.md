# Plan: web incident forensics tool

Status: **Approved.** M0–M6 complete. Extended on 2026-10-29 with M8 (realistic benchmark) and M9 (wider coverage), D82.

| Milestone | State |
|---|---|
| M0 scaffold | done: pyproject, Typer CLI, ruff, pytest, GitHub Actions |
| M1 models + FileAdapter + parsers + collect.sh | done: collect.sh verified on Linux CI |
| M2 | done: log rules, file rules, isolated lab-lite stack, spaced Scenario A and F replays, collected evidence, benchmark schema/validation |
| M3 | done: file-first correlation engine (`correlate/`), baseline comparison, anchor + timestomp check, gaps + confidence, MITRE table, proxy-aware actors, login outcomes, weak seeds, error-log parser, indexed engine (1M lines in ~27 s); scenario A/F acceptance plus noisy variants (precision), gap fixtures, seeded property test |
| M4 | done: Indonesian report (`report/`: builder, format-neutral document, Markdown + self-contained HTML + JSON), `analyze` command, CSIRT-phase recommendations, grouped background noise, evidence scope, attack story, raw root-cause request, versioned report.json; golden files for A/F, byte-identical reruns from any working directory, escaping and well-formed HTML tests, catalog coverage test |
| M5 | done: `eval` command and metrics (D68), schema for no-compromise and held-out scenarios, lab scenarios B (POST SQLi), D (busy, no compromise, baseline), E (held-out, timestomp) behind a loopback edge proxy, with PHP upload messages in nginx's error log (`fastcgi.logging`); `vulnerable_code` pinned to the source file's SHA-256 (the lab app changed between A/F and B/D/E, which matters for M7); golden reports for all five scenarios; D's first run found a writer-ranking bug (D69) and a proxy bug in the noise table (D70); its report now flags a successful-looking SQLi login bypass outside any incident (D71); all five scenarios fully correct |
| M6 | done: WazuhAdapter (`pull`, `analyze --wazuh-recording`, D73–D81); live lab test agrees with the FileAdapter on all five scenarios; benchmark re-recorded with Wazuh recordings, `eval` scores both adapters (all fully correct) |
| M7 | done: PHP SQLi localization (`codeloc/`, D83) on implicated files, prepared-statement fixes in the report; lab app and hand-made fixtures correct; real CVE fixes 5/13 detected (8 misses out of scope), 0 findings on fixed code; eval Code line column |
| M8 | in progress: first independent case done (Ali Hadi "Web Server Case", answer key written before the run; run 1 found 10 false accusations, a missed root cause and an unreadable report; general fixes D84, D85; benchmark/external/). Second case held out (Ali Hadi Linux web server): run 1 poor (missed exploit, wrong root cause, 1 false IP, 2 false files), fixes D86. Third case held out (BND 2016): run 1 missed the compromise (defacement, cut log), fixes D87. Fourth case held out at real scale (Zenodo 20001206, 7.6M lines): no false accusations, admin-panel incident missed, memory and report-size limits found, fixes D88; one run over all sites then showed scripts must be keyed by site, D89. Next: more untouched cases, then benchmark v2 (real apps, real attack tools, real background logs, third-party ground truth) |
| M9 | planned: wider coverage (more attack classes, log tampering check against Wazuh, log formats, multi-server, M6+) |
Source of truth: `CLAUDE.md`. Design decisions are logged in `docs/decisions.md` (referenced here as D1, D2, ...).

---

## 1. Clarifying questions — resolved

| # | Question | Answer | Effect on design |
|---|----------|--------|------------------|
| Q1 | How will the webroot reach the tool? | Default: `collect.sh` produces a tar plus a stat manifest. | The FileAdapter trusts the manifest's path, size, mtime, ctime, btime, inode, uid, mode, and sha256, not the copied files' metadata. A plain folder with no manifest is supported, but its confidence is downgraded (D9). |
| Q2 | Is a known-good baseline available? | Default: optional. | `--baseline` accepts a manifest or a git dir. With no baseline, the run records a `no_baseline` evidence gap and file status comes from heuristics only (D19). |
| Q3 | Lab SQLi: GET, POST, or both? | **Both.** | Scenario A uses GET-based SQLi (visible in logs). Scenario B uses POST-based SQLi (payload invisible in access logs; inferred from timing and endpoint, with lower confidence) (D20). |
| Q4 | Lab-lite earlier? | **Yes**, in M2, without Wazuh. | M2 now includes nginx + PHP + MySQL generating scenario A evidence (D18). |
| Q5 | Wazuh version? | No instance yet. Target the latest stable release at install time, and record the exact version in the docs. | M6 starts by installing Wazuh in the lab, then writes `docs/wazuh-notes.md` with the version and the doc pages it was verified against (D21). |

The brief corrections in §6 are accepted. Wazuh **pull** (reading alerts and syscheck/FIM data) stays core. Wazuh **trigger and write-back** are stretch goals (D22).

---

## 2. Repo structure

```
web-forensics/
├── pyproject.toml              # hatchling, deps, ruff + pytest config
├── README.md
├── CLAUDE.md
├── src/webforensics/
│   ├── __init__.py
│   ├── cli.py                  # Typer app: analyze, eval, collect-manifest
│   ├── config.py               # settings (timezone, docroot→URL map, thresholds)
│   ├── models.py               # pydantic models (section 3)
│   ├── adapters/
│   │   ├── base.py             # LogSource, FileEvidenceSource Protocols
│   │   ├── file_adapter.py     # log files + webroot/manifest
│   │   └── wazuh/              # M6: indexer client, syscheck, writeback
│   ├── parsers/
│   │   ├── access_log.py       # nginx/apache combined (+ custom format string)
│   │   └── error_log.py
│   ├── detect/
│   │   ├── log_rules.py        # SQLi / traversal / upload / scanner classifiers
│   │   ├── file_rules.py       # webshell + persistence heuristics
│   │   └── rules/*.yaml        # signatures, versioned, each with a rule_id
│   ├── correlate/
│   │   ├── engine.py           # file-first correlation (section 4)
│   │   ├── timeline.py
│   │   ├── gaps.py             # evidence-gap detection
│   │   └── confidence.py       # deterministic confidence rules
│   ├── attack/mitre.py         # static technique table
│   ├── codeloc/php_sqli.py     # M7
│   ├── analysis.py             # load evidence -> correlate -> build report (used by the CLI)
│   ├── report/
│   │   ├── build.py            # language-neutral Report: summary, recommendations, noise groups
│   │   ├── document.py         # format-neutral sections/tables of plain text
│   │   ├── markdown.py, html.py  # serializers, one escape function each (D58)
│   │   ├── text.py             # keys -> Indonesian text, report time zone
│   │   └── messages_id.py      # Indonesian strings catalog
│   └── llm/                    # optional, off by default (late / roadmap)
├── tests/
│   ├── unit/
│   ├── integration/            # runs full pipeline on benchmark scenarios
│   └── fixtures/               # tiny logs, manifests, defanged PHP samples
├── scripts/collect.sh          # server-side evidence collector (read-only)
├── lab/
│   ├── docker-compose.yml      # internal network only
│   ├── app/                    # intentionally vulnerable PHP app
│   ├── nginx/
│   ├── wazuh/                  # M5/M6
│   └── attacks/                # scripted request replays, one per scenario
├── benchmark/
│   ├── README.md               # how to run your own tool against it
│   ├── schema/ground_truth.schema.json
│   └── scenarios/<id>/
│       ├── evidence/           # logs/, manifest.json, webroot.tar
│       └── ground_truth.json
└── docs/
    ├── plan.md  decisions.md
    ├── architecture.md  evaluation.md  limitations.md
```

The core reason for this layout: `adapters/` is the only place that knows where evidence comes from, and `correlate/` only sees models. That makes the Wazuh adapter a drop-in, and the core testable without Docker (D3).

---

## 3. Data models

All models are pydantic v2 (D2), immutable, and JSON-serializable. All timestamps are timezone-aware UTC (D6).

### Citation (shared building block)
| Field | Why |
|---|---|
| `kind`: `log_line` \| `file` \| `wazuh_alert` | Tells the renderer how to display it. |
| `source`: str | Log file path, file path in the webroot, or Wazuh index/doc id. |
| `line_no`: int \| None | Required for `log_line`, so an analyst can open the log and jump to the line. |
| `sha256`: str \| None | Required for `file`. Proves which file version we mean, even if it changes later. |
| `excerpt`: str | The raw line or snippet (truncated). Lets the report stand alone. |

### Evidence (base)
| Field | Why |
|---|---|
| `evidence_id`: str | Deterministic hash of (source, locator), so it is stable across runs (D7). |
| `adapter`: str | Which adapter produced it (`file`, `wazuh`). Provenance. |
| `source`: str | Original location. |
| `collected_at`: datetime \| None | From the manifest/collector. Separates the "when we looked" time from the "when it happened" time. |

### FileEvidence(Evidence)
| Field | Why |
|---|---|
| `path`: str (relative to webroot) | Needed to map the file to a URL. |
| `url_paths`: list[str] | Derived via the docroot→URL map. This is how the file joins to log requests. |
| `sha256`, `size` | IOC, plus citation integrity. |
| `mtime`, `ctime`, `btime`?, `atime`? | Anchors for the time window. Each is optional because sources differ. |
| `timestamp_source`: `manifest` \| `live_stat` \| `wazuh_fim` \| `copied` | Trust level of the timestamps (D10). |
| `inode`, `uid`, `mode` | Odd inode ordering or owner `www-data` in code dirs are supporting signals. |
| `baseline_status`: `new` \| `modified` \| `unchanged` \| `unknown` | Result of comparing against a baseline, if one exists. |
| `content_ref`: str \| None | Path to the extracted content for static analysis. The content is never executed (D15). |

### LogEvent(Evidence)
| Field | Why |
|---|---|
| `log_file`, `line_no`, `raw` | Mandatory for citations. |
| `ts`: datetime | Normalized to UTC. |
| `ts_semantics`: `request_start` \| `request_end` | Apache `%t` is the request start, while nginx `$time_local` is the time the log is written (≈ end). This matters for tight windows. |
| `client_ip`, `xff`: str \| None | The real attacker may sit behind a proxy or CDN. |
| `method`, `path`, `query`, `status`, `bytes`, `referer`, `user_agent` | Inputs for detection. |
| `vhost`: str \| None | Multi-site servers. |
| `tags`: list[str] | Filled by `detect/` (e.g., `sqli`, `upload_endpoint`, `webshell_access`). |

### Finding
| Field | Why |
|---|---|
| `finding_id` | Stable id. |
| `rule_id`, `rule_version` | Explainability and reproducibility: you can see which rule fired, and which version of it. |
| `category`: `exploit_attempt` \| `exploit_success` \| `webshell` \| `persistence` \| `recon` \| `anti_forensics` | Drives the timeline phases. |
| `subject`: evidence_id | The file or request this finding is about. |
| `severity`, `confidence` | Separate on purpose. A severe finding can still be uncertain. |
| `reasons`: list[str] | Machine keys plus params, e.g. `("dangerous_func_with_request_input", {"func": "system"})`. Rendered in Indonesian later. |
| `citations`: list[Citation] (≥1) | Mandatory. |
| `mitre`: list[str] | e.g. `T1505.003`. |

### TimelineEvent
| Field | Why |
|---|---|
| `ts`, `ts_basis`: `log` \| `ctime` \| `btime` \| `mtime` \| `fim` \| `inferred` | Readers must know whether the time is a logged fact or a file-metadata estimate. |
| `phase` / `mitre_tactic`, `mitre_technique` | ATT&CK mapping. |
| `actor`: str \| None | Client IP (or IP+UA cluster). |
| `description_key` + `params` | Language-neutral, rendered via `messages_id.py`. |
| `citations`: list[Citation], **min 1, enforced by validator** | Brief requirement (D4). |
| `confidence`: `high` \| `medium` \| `low` + `confidence_reasons` | Categorical, not fake-precise floats (D5). |
| `finding_ids` | Back-reference. |
| `is_root_cause`: bool | Highlight in the report. |

### EvidenceGap
`start`, `end`, `source`, `kind` (`no_log_lines`, `rotation_boundary`, `parse_errors`, `missing_timestamps`, `clock_skew_suspected`, `no_baseline`, `post_body_not_logged`), `affects`: list of timeline/finding ids. Gaps get their own model so they can be listed and attached to the conclusions they weaken.

### Report
| Field | Why |
|---|---|
| `case`: id, title, analyst, target host (redactable) | Report header. |
| `run`: tool version, ruleset version, input file hashes, config hash, `generated_at` (injected) | Reproducibility: the same inputs and the same version give the same report (D7). |
| `summary`: key + params | Executive summary (Ringkasan). |
| `timeline`: list[TimelineEvent] | Sorted by (ts, evidence order). |
| `root_cause`: RootCause \| None, plus `alternative_candidates` | Never forces a single answer when the evidence is ambiguous (D11). |
| `affected_files`: list[FileEvidence + verdict] | |
| `iocs`: ips, user_agents, hashes, paths, urls | Copy-paste for blocking or hunting. |
| `gaps`: list[EvidenceGap] | Brief requirement. |
| `code_findings`: list[CodeLocation] (M7) | file, line, snippet, vuln class, suggested fix, confidence. |
| `recommendations`: list[key] | Tindakan yang disarankan, following the CSIRT flow (containment, eradication, recovery, lessons learned). |
| `limitations`: list[key] | Standard honest caveats. |

---

## 4. Correlation algorithm (file-first)

**Step 0: Normalize.** Parse every log line, keeping the file and line number. Convert timestamps to UTC and record unparseable lines as gaps. Hash every file. If a baseline exists, label each file new, modified, or unchanged.

**Step 1: Seed suspicious files.** Run the file rules (dangerous function fed by `$_GET/$_POST/$_REQUEST/$_COOKIE`, executable extension in an upload/writable dir, known signatures, high entropy or obfuscation, modified `.htaccess`/index). Each hit becomes a `Finding` and its file becomes a seed.

**Step 2: Choose the anchor time T for each seed.** Use btime or ctime if available, because userland `touch` cannot set ctime. Compare with mtime: if mtime < ctime by a large margin, raise an `anti_forensics` (T1070.006 timestomp) finding and anchor on ctime. If only mtime is available, the confidence of everything derived from it is capped at **medium** (D10).

**Step 3: Find invocation requests.** Map the file to its URL(s) and select all log events hitting that URL. The first request gives "first use". Look at the IPs, POSTs to a rarely-hit file, and query strings that look like commands. Invocations before T suggest the anchor is wrong (timestomp or overwrite) and get flagged.

**Step 4: Find creation-candidate requests.** Look in a window `[T − Δ, T + skew]` (default Δ = 120 s, skew = 5 s, both configurable). Rank candidates deterministically by:
1. write-capable semantics (POST to upload endpoint, `INTO OUTFILE`, traversal + write, CMS plugin install),
2. 2xx status,
3. same IP/UA as the invocation requests,
4. time distance to T.

The top candidate becomes the "creation" event. If two candidates score within a margin, both are kept as alternatives.

**Step 5: Trace back to the root cause.** Starting from the creation request's actor (IP, plus UA cluster), walk backwards through that actor's requests. Find the **earliest successful exploit** that the creation step depends on (e.g., SQLi login bypass → authenticated upload). Recon (404 bursts, scanner UAs) is attached as context but is not the root cause. If the creation request is itself an exploit (an unauthenticated upload), it is the root cause.

**Step 6: Trace forward.** List the actor's later requests to the webshell, any further new or modified files, and `.htaccess`/cron changes. These are post-exploitation and persistence events.

**Step 7: Detect gaps.** Look for log silence significantly longer than the baseline request rate, rotation boundaries, gaps around T, and missing sources (no error log, no baseline). Attach each gap to the events it weakens and lower their confidence.

**Step 8: Assemble.** Map to MITRE. Compute confidence from explicit rules (e.g., `high` = log fact + file hash + same actor; `medium` = one inferred link; `low` = mtime-only or within a gap). Sort and emit the `Report`.

### Weaknesses (these go into `docs/limitations.md` and the report)
- **mtime forgery:** `touch -d` is trivial. ctime survives userland tampering but not root changing the clock or `debugfs`. We detect inconsistency; we cannot prove integrity.
- **Snapshot copying destroys timestamps:** that is why there is a collector plus manifest (Q1).
- **POST bodies are not logged:** upload filenames and POST-based SQLi payloads are invisible, so the link is inferred from timing and endpoint only. The confidence reflects this.
- **Missing logs or rotation:** rotated `.gz` files are supported if provided, but deleted logs are simply gone. If the attack predates log retention, the root cause can be "unknown". The tool must be willing to say that.
- **Log tampering:** an attacker with root can delete lines. We can only detect it indirectly (gaps, non-monotonic timestamps).
- **Multiple attackers / opportunistic scanners:** many IPs fire SQLi payloads at public sites. Attributing the shell to the right actor depends on the IP/UA linkage. Shared NAT, proxies, or a CDN without XFF make this ambiguous. When that happens, we output alternative candidates instead of guessing.
- **Non-HTTP entry:** files dropped via SSH/FTP/CI or a legitimate admin upload have no matching malicious request. The tool must report "no HTTP creation request found", not invent one.
- **Clock skew and 1-second log resolution:** relevant mostly when Wazuh and the web server timestamps are combined.
- **nginx request_end vs. request_start timing:** long uploads shift log time relative to file creation.

---

## 5. Milestones (target 5–6 weeks)

Every milestone ends with `ruff check`, `pytest` green, updated docs, and one commit (only after you approve each one).

| # | Milestone | Done when |
|---|-----------|-----------|
| **M0** | Scaffold: pyproject (hatchling), Typer CLI skeleton, ruff, pytest, GitHub Actions CI, README stub | `webforensics --help` works; `pytest` and `ruff check` pass in CI on an empty test. |
| **M1** | Models + FileAdapter + log parsers + `collect.sh` manifest format | Unit tests: nginx and Apache combined fixtures parse with correct line numbers and UTC times; malformed lines are counted, not crashed on; a manifest loads into `FileEvidence` with sha256 and timestamps; a `TimelineEvent` without a citation **fails validation**. |
| **M2** | Detection rules (log + file) + **lab-lite** (nginx + PHP + MySQL, scenario A generated) | Labeled fixture tests: each rule has ≥2 positive and ≥2 negative cases. Lab-lite `docker compose up` + `attacks/scenario_a.py` produces logs and a manifest under `benchmark/scenarios/a/`. |
| **M3** | Correlation engine + timeline + gaps + confidence | On scenario F: the timeline traces back from the uploaded file to the SQLi root-cause request, in order. On scenario A: the unauthenticated upload is the root cause and the earlier SQLi probe is **not** blamed. A property test confirms every event has ≥1 citation. A gap fixture (deleted log hour) produces an `EvidenceGap` and lowers confidence. |
| **M4** | Indonesian report (MD + HTML) + `analyze` command end to end | Golden-file tests for both formats. **Determinism test:** two runs give byte-identical output. HTML escapes attacker-controlled strings (a test with a `<script>` UA). |
| **M5** | Full lab + benchmark + `eval` command | Scenarios: **A** GET-SQLi probe as a distractor + unauthenticated upload as root cause (replaces the old "direct upload" scenario C). **F** SQLi login bypass → authenticated upload (SQLi is the root cause). **B** POST-SQLi variant of F. **D** benign multi-client noise with no compromise (tests false accusations; benign traffic must come from IPs other than the attacker's). **E** timestomped upload. Each has a `ground_truth.json` validated against the schema. `webforensics eval benchmark/` prints step recall, precision, root-cause correctness, and runtime, and that table is pasted into the README. |
| **M6** | **WazuhAdapter (pull, core):** install the latest stable Wazuh 4.14.x single-node in the lab with archives on (D73, D74); `pull` web events from `wazuh-archives-4.x-*` (alerts-only as a degraded mode) and FIM events from `wazuh-alerts-4.x-*` into a recording (D78); `analyze` reads the recording offline, re-parsing `full_log` with the existing parser (D75). Core changes: FIM time fields and anchor (D76), hash-matched `--webroot` content (D77), deleted files (D78), alerts-only gap handling (D74) | `docs/wazuh-notes.md` records the exact installed version and the doc pages and source files each detail was verified against. Done when the lab scenarios analyzed via WazuhAdapter (realtime FIM + archives) give the same root cause and affected files as via FileAdapter (integration test, marked `@lab`). Unit tests and the benchmark run on recorded JSONL, so no live Wazuh is needed in CI; `eval` gains an `adapter` column. If W5 slips, cut in this order: deleted-file handling (finding only), `--webroot` content, alerts-only mode. |
| M6+ | *Stretch:* Wazuh trigger (integration/active-response invokes the tool on a webroot-FIM or web-attack alert) + write-back (findings → event → custom decoder/rule) | Only if M7 is done and time remains. Done when a FIM alert in the lab triggers an analysis, and a write-back finding appears as a decoded Wazuh alert. |
| **M7** | PHP SQLi code localization | On the lab app plus ≥10 small PHP fixtures (positive and negative, incl. prepared statements and sanitized ints): reports the vulnerable line plus a prepared-statement fix. The eval table gains "line localization accuracy". Added by D82: part of the fixtures come from SQLi CVEs in open-source PHP projects, where the lines changed by the upstream fix commit are the ground truth (written by someone other than the rule author). |
| **M8** | Benchmark v2: as close to real incidents as an isolated lab allows (D82) | Real vulnerable applications (published upload/SQLi CVEs, DVWA/bWAPP-style apps) attacked by real tools (sqlmap, Weevely, commix, login brute force), mixed into real public access-log traffic. Some scenarios authored and attacked blind by third parties, and public DFIR cases if any include webroot plus logs. 30–50 scenarios including benign traps (CMS/plugin updates, caches, legitimate uploads); held-out split frozen before any tuning; every failure reported. Both adapters scored. Lab, attack and sample work goes to Codex; Claude verifies. |
| **M9** | Wider coverage (D82) | Attack classes: path traversal/LFI to RCE, command injection, brute force or stolen credentials then upload, CMS theme/plugin editor writes, `.htaccess` persistence. Log tampering evidence: lines present in Wazuh archives but missing from the server's log. Optional POST evidence from ModSecurity audit logs. nginx/Apache JSON and vhost log formats. Several webroots/logs behind a load balancer. M6+ trigger and write-back. Each item ships with benchmark scenarios. |

Rough schedule: W1 = M0–M1, W2 = M2 (incl. lab-lite), W3 = M3–M4, W4 = M5, W5 = M6 (pull only), W6 = M7 + README/docs polish. D82 adds roughly 3–5 weeks for M8 and M9. A UI stays out of scope. The Wazuh trigger/write-back and the optional LLM layer happen only if time remains; otherwise they stay on the README roadmap.

---

## 6. Risks and problems with the brief (honest list)

1. **Scope vs. 5–6 weeks.** *Accepted:* the Wazuh trigger and write-back are now stretch goals, and pull stays core. The schedule is still tight. If it slips, M7 is cut down to the lab app plus a small fixture set before anything else is dropped.
2. **The pitch says "points to the vulnerable line" but MVP excludes it.** README and CV wording must not claim it until M7 is done.
3. **Self-made benchmark bias.** You write the attacks, the ground truth, and the rules, so you will overfit. Mitigations: write scenarios D and E *before* tuning rules, add realistic benign noise (crawlers, legit uploads), keep one held-out scenario, and say this openly in `evaluation.md`. Reviewers will respect it more than a 100% score.
4. **POST-body blindness** (see section 4). It is the biggest technical limitation of log-based correlation, and the README should state it up front.
5. **Wazuh FIM timestamps may be detection time, not modification time.** *Verified (M6):* the alert `timestamp` is manager processing time. It is a tight upper bound in realtime mode and up to 12 h late in scheduled mode, and `mtime_after` has a time-zone bug. Handled by D76.
6. **Wazuh write-back (stretch):** the usual pattern is probably "write a JSON line to a file the agent monitors + custom decoder/rule", not writing into the indexer directly. To verify, not assume (as the brief already says).
7a. **No Wazuh instance yet:** installing it in the lab costs time (and RAM: a single-node Wazuh with indexer is heavy for a laptop). That cost lands in W5. Mitigation: CI and unit tests use recorded JSON fixtures, and only the `@lab` integration test needs the live stack.
7. **Antivirus on this Windows machine and GitHub.** Real webshell signatures in `tests/fixtures` or `benchmark/` will likely be quarantined by Defender, and may get the repo flagged. Use **defanged/synthetic samples** and store any known-bad signatures as hashes or split strings. This also applies to the lab app.
8. **Developing on Windows:** `os.stat().st_ctime` means *creation* time on Windows, not inode-change time. Core tests must use manifests, never host filesystem timestamps. The lab and collector are Linux-only.
9. **The report itself is an attack surface:** user agents, paths, and file contents are attacker-controlled. Mandatory HTML escaping, plus never executing or `include`-ing evidence (D15).
10. **PHP parsing from Python:** there is no mature pure-Python PHP parser. The likely choice is tree-sitter-php. The fallback is a token/regex heuristic with lower confidence. *Resolved in M7:* tree-sitter-php works with prebuilt wheels; no fallback needed (D83).
11. **The comparison with other tools** (ais, WebLogForensics, LORG, ShadowPulse) is not verified yet. It is a README task before any claim is written, as the brief says.
12. **"CSIRT incident-handling flow" in Indonesian.** I will structure the report around generic NIST/CSIRT phases. If you want to align it with a specific Indonesian guide (e.g., from BSSN), tell me which document. I won't cite one I haven't checked.

---

## 7. Open follow-ups (carried over from M0–M2 reviews)

Small items deliberately deferred. Each lists the milestone where it belongs.

**For M4 (report + `analyze`): done**
- `analyze` takes `--baseline`, error logs, trusted proxies and the creation-window and clock-skew thresholds.
- Every key the engine can emit has Indonesian text. `tests/unit/test_messages.py` scans the source and renders real results in strict mode.
- Unattributed findings are grouped per rule in their own section (D62).

**Still open after M4**
- The report has no vulnerable-code section until M7 (`limit.no_code_analysis` says so).
- Recommendations are rules over the result, not tailored advice. They are worded as checks to do, and the report says an analyst must verify it.
- The silence, lonely-write and rare-POST thresholds are not on the CLI yet. Defaults are in `correlate/config.py`.

**Correlation limits found in M3: fixed in M3 (D47–D51)**
- Actor = client IP only → XFF from trusted proxies (right-most untrusted hop); a user-agent switch between entry point and write lowers confidence.
- Login 200-on-failure → outcome from 401/403/429, retry-before-using-the-area, and same (status, size) as a known failure.
- "POST to a rarely-hit file" → `CORR-RARE-POST-TARGET`.
- Night-time false gaps → silence threshold from the local request rate (±25 intervals).
- `.php` outside upload dirs with no content/baseline → "lonely write" weak seeds; unlinked ones go to `unexplained_changes`.
- Error-log parser → nginx + Apache, used to corroborate and as a low-confidence fallback creator.

**Limits that remain (inherent to the evidence, documented for the report)**
- POST bodies are not logged: POST-SQLi payloads and upload file names stay invisible. The engine can only say "a login of unknown method" (LOW).
- Shared IPs without XFF (NAT, untrusted CDN) still merge people. The UA check only flags it.
- Login outcomes are inferred. A failure page whose size changes on every attempt (e.g. it echoes the username), followed by no retry, still reads as a success.
- Error-log time has no UTC offset. A wrong `--error-log-utc-offset` silently breaks matching, so every error-log citation carries the offset that was assumed.
- A deleted log hour inside a quiet period is indistinguishable from no traffic.
- CMS-generated `.php` files are now set aside for review (D56), but this was only checked against synthetic noise. Scenario D in the lab still has to confirm it.
- Memory: about 1.1 GB peak for 1M lines when 1 in 8 is a bot payload (`docs/performance.md`). Streaming would fix it; deferred.
- Error logs and XFF are only covered by synthetic tests. The lab doesn't produce them yet (add in M5).

**For M5 (benchmark + eval)**
- `tests/integration/test_benchmark_scenarios.py` checks all scenarios in one loop. Parametrize per scenario so each shows up as its own test.
- Ground-truth step categories are free text (`unrestricted_upload`, `successful_login_bypass`, ...). Map them to `FindingCategory` before building `webforensics eval`.
- All lab traffic comes from one IP (the Docker host gateway), so attacker vs. visitor attribution is untested. Scenario D needs benign traffic from other IPs (e.g., a second client container).
- Scenario F's login uses GET so the SQLi shows in logs. Scenario B is the POST variant.
- Don't commit regenerated evidence casually. A replay keeps the same structure (same line numbers, same marker hash), so the current ground-truth test still passes. But timestamps and manifest rows change, which will break M3/M5 tests and report golden files that pin exact values. Regenerate on purpose, then update those expectations in the same commit.

**Rules (any time)**
- Rules are Python, not YAML as D8 originally said. Revisit only if signatures grow large.
- Known rule limitations: see D29 and D30 (`base64_decode` noise, no taint tracking through variables).

**Before making the repo public**
- Choose a license (MIT or Apache-2.0).
- Verify the comparison with related tools (risk 11).
- Review every sample and lab artifact for anything that looks functional (D16).
- Note in `lab/README.md` that nginx's host-access bridge gives the nginx container outbound network access.

**Working setup**
- Lab, vulnerable-app and attack-replay work is done by Codex on a feature branch. Claude writes the prompt, then verifies (tests, ruff, `inspect`, ground-truth consistency) and merges.
- Codex's sandbox cannot use `.venv` (built from Windows Store Python 3.11). Always re-run `.venv\Scripts\python -m pytest` locally, and install any dependency Codex adds to `pyproject.toml`.

---

## Next step
**M4: Indonesian report (MD + HTML) + `analyze` command.** Render `CorrelationResult` through a string catalog (`report/messages_id.py`) and Jinja templates; golden-file tests, a byte-identical determinism test, and an HTML-escaping test with a `<script>` user agent.
