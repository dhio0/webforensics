# Wazuh notes (M6)

Status: **verification done from docs and source code; nothing installed yet.** Checked on 2026-10-29.

Each claim cites one of three kinds of source:
- **[doc]**: an official Wazuh or OpenSearch documentation page.
- **[src]**: Wazuh source at tag `v4.14.9`, i.e. `https://github.com/wazuh/wazuh/blob/v4.14.9/<path>`.
- **[lab]**: not answerable from docs or source. Must be confirmed on the live lab before the adapter relies on it.

Source code beats docs: where they disagree, or the docs are silent, the source wins.

## 1. Target version

- **Wazuh 4.14.9** (14 Oct 2026) is the newest stable release, marked *Latest* on GitHub. Newer tags are pre-releases only: `v4.14.10 RC 1`, `v5.0.0-rc1`.
  - [doc] https://documentation.wazuh.com/current/release-notes/index.html
  - https://github.com/wazuh/wazuh/releases
- Per D21 ("latest stable at install time"), the lab pins the newest **4.14.x** tag on install day: `v4.14.9` today, or `v4.14.10` if it goes GA first. The adapter supports 4.14.x only.
- The Wazuh indexer 4.14.9 is built on **OpenSearch 2.19.6** ([src] `wazuh/wazuh-indexer` `buildSrc/version.properties` at `v4.14.9`).

### Wazuh 5.0 breaks this adapter

The 5.0-rc docs replace `wazuh-alerts-*` / `wazuh-archives-*` with `wazuh-events-v5-*`, `wazuh-findings-v5-*` and `wazuh-events-raw-v5`, and add `wazuh-states-fim-files`.
- [doc] https://documentation.wazuh.com/5.0-rc/user-manual/wazuh-indexer/wazuh-indexer-indices.html

**Version detection.** The indexer's `GET /` reports the OpenSearch version, not the Wazuh version. The official index template applies to exactly `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*` ([src] `extensions/elasticsearch/7.x/wazuh-template.json`). So the adapter queries those names explicitly. On 5.x it gets "no such index" and stops with a clear message instead of returning empty results. 5.x support is roadmap.

## 2. Lab deployment (Docker, single node)

[doc] https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html

**Steps.**
1. `git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.9`, then `cd single-node`.
2. `docker compose -f generate-indexer-certs.yml run --rm generator`.
3. `docker compose up -d`.

**Requirements and ports.**
- ≥4 CPU cores, **≥8 GB RAM for the Docker host**, ≥50 GB disk.
- `vm.max_map_count=262144`, set inside WSL 2 on Windows.
- Ports: 1514/1515, 514/udp, 55000 (server API), **9200 (indexer)**, 443 (dashboard). Default credentials are `admin` / `SecretPassword`; change them.

**Agent image.** `wazuh/wazuh-agent:4.14.9` exists. The docs say a containerized agent cannot monitor the host. That doesn't affect us: the agent only needs the `webroot` named volume (read-only) and the nginx log directory.

**Host.** 15.7 GB RAM, 16 logical CPUs, and no `%USERPROFILE%\.wslconfig`. The WSL 2 VM gets the default "50% of total memory on Windows" ([doc] https://learn.microsoft.com/en-us/windows/wsl/wsl-config), about 7.8 GB, which is below Wazuh's minimum. **Done (2026-10-29):** `memory=10GB` in `.wslconfig`; the Docker VM now reports 9.7 GiB.

**Lab constraints.**
- **Order.** Wazuh must run **before** the attack replay:
  - FIM builds its baseline on start ("Syscheck always runs a scan when it starts", [doc] syscheck reference).
  - Logcollector's `only-future-events` defaults to `yes`: "when wazuh-logcollector is started it reads the logs generated since that moment" ([doc] https://documentation.wazuh.com/4.14/user-manual/reference/ossec-conf/localfile.html).
- **Time zone.** All Wazuh containers run with `TZ=UTC` (see §4, `mtime_after`).
- **Network.** Wazuh joins the lab's internal network. Only 9200 and the dashboard are published, on `127.0.0.1` (D31 style).
- **Realtime FIM.** inotify watches inodes in the kernel, and both containers share the same named volume on the same Docker VM kernel. So realtime FIM should see writes by the PHP container. It is expected but **[lab]**. Fallback: scheduled FIM with a short `frequency`, recorded as such in the benchmark.

## 3. Web logs

### 3.1 Alerts alone are not enough (key finding)

`log_alert_level` defaults to **3** ([doc] https://documentation.wazuh.com/4.14/user-manual/reference/ossec-conf/alerts.html).

Web rules ([src] `ruleset/rules/0245-web_rules.xml`, raw XML checked):
- **Level 0, never alerted:**
  - 31100 is the base rule for every access-log line.
  - 31108 matches "simple" 2xx/3xx requests.
- **Alerted:**
  - 31103 SQLi (level 7)
  - 31104 traversal/common attack (6)
  - 31105 XSS (6)
  - 31106 "attack returned 200" (6)
  - 31164/31165/31170/31171 encoded SQLi (6)
  - 31101 4xx (5)
  - frequency rules 31151–31153 (10)

So ordinary successful requests never reach `wazuh-alerts-*`: the upload POST, the webshell POST, and scenario B's POST-body SQLi. Those are the requests file-first correlation depends on.

**Fix: `wazuh-archives-*`**, "all events sent to the Wazuh server". It is **off by default**. To enable it, set `<logall_json>yes</logall_json>` in the manager's `ossec.conf` and `archives: enabled: true` in Filebeat.
- [doc] https://documentation.wazuh.com/4.14/user-manual/wazuh-indexer/wazuh-indexer-indices.html
- [doc] https://documentation.wazuh.com/4.14/user-manual/manager/event-logging.html

**Archive and alert JSON have the same shape [src].**
- Archives are written by `jsonout_output_archive()` (`src/analysisd/output/jsonout.c`), which calls the same `Eventinfo_to_jsonstr()` as alerts. It passes `force_full_log = true`, so every archive event carries `full_log`.
- `rule` is present only when a rule matched.
- Both indices use the same ingest pipeline: `timestamp` is copied to `@timestamp`, and the daily index name is derived from `timestamp` (`extensions/filebeat/7.x/wazuh-module/*/ingest/pipeline.json`).

### 3.2 Decoded fields are too thin; re-parse `full_log`

The `web-accesslog*` decoders extract only `srcip`, `protocol` (the method), `url` and `id` (the status). There is no request time, UA, bytes or referer ([src] `ruleset/decoders/0375-web-accesslog_decoders.xml`, raw XML checked). `srcip` is the first field of the line, so behind our edge proxy it names the proxy.

**Design.** The adapter runs our existing access-log parser on `full_log`. That gives us the request time from the log itself, the UA, and trusted-proxy XFF (D47). It also means one parser for both adapters.

Wazuh's `rule.id` (31103, …) is shown in the citation excerpt for the analyst, but it is **not used in scoring**. Our rules decide, so both adapters score the same way.

### 3.3 Event time and IDs [src]

- **`timestamp`** is set by analysisd when it decodes the event: `gettime(&lf->time)` in `OS_CleanMSG` (`src/analysisd/cleanevent.c`). So it is **manager receive/processing time**, not log time and not agent time.
- It is formatted in the manager's local time with milliseconds and a correct `%z` offset (`W_JSON_AddTimestamp`, `src/analysisd/format/json_extended.c`).
- **`id`** is `"<epoch sec>.<global counter>"` (`src/analysisd/format/to_json.c`). An archive copy and an alert copy of the same line get **different** ids, so dedup by `id` is impossible. The design doesn't need it: web events come from one index, FIM from the other.
- **`location`** holds the source path and there is **no line number**. Citations are `wazuh_alert` with `source = <index>/<_id>`, plus `location` and the `full_log` excerpt. The report says explicitly that the line number is not available from Wazuh.

## 4. FIM (syscheck)

### 4.1 Modes and attributes

[doc] https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html, https://documentation.wazuh.com/4.14/user-manual/capabilities/file-integrity/advanced-settings.html

- **Modes:**
  - **scheduled** is the default, every `frequency` = 43200 s (12 h);
  - **realtime** uses inotify, works on directories only, and "pauses during scheduled scans";
  - **whodata** uses audit or eBPF on Linux and adds `audit.user.*` and `audit.process.*`.
- **`syscheck.mode` values:** `scheduled`, `realtime`, `whodata` ([src] payload schema comment in `decode_fim_event`, `src/analysisd/decoders/syscheck.c`).
- `check_all` = yes covers MD5/SHA-1/SHA-256, size, owner, group, perm, mtime and inode. There is **no ctime or btime**.

### 4.2 Rules and fields

[src] `ruleset/rules/0015-ossec_rules.xml`: **554** added (level 5), **550** modified (7), **553** deleted (7). All are ≥3, so FIM events are always in `wazuh-alerts-*`.

Fields:
- `syscheck.path`, `.event` (`added`/`modified`/`deleted`), `.mode`
- `sha256_after`, `size_after`, `perm_after`, `uid_after`, `uname_after`, `inode_after`, `mtime_after`, `changed_attributes`
- `*_before` fields when a value changed

Sources: [doc] https://documentation.wazuh.com/4.14/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html and [src] `to_json.c`.

**Deleted files keep their last hash [src].** The agent builds a delete event with `fim_json_event(entry, …)` from the stored DB entry (`process_delete_event`, `src/syscheckd/src/create_db.c`). So `deleted` alerts carry the file's last known `*_after` attributes, including `sha256_after`. A deleted webshell can therefore still be represented with a hash. Expected; confirm in the lab.

### 4.3 The `mtime_after` time zone bug (resolved from source, confirmed in the lab)

[src] `src/analysisd/format/to_json.c`:

```c
char mtime[25];
localtime_r(&aux_time, &tm_result);
strftime(mtime, 20, "%FT%T%z", &tm_result);
```

- The epoch mtime from the agent is converted on the **manager**, in the **manager's** local time zone.
- The buffer limit of 20 has room for `YYYY-MM-DDTHH:MM:SS` plus the NUL only, so the `%z` offset is cut off.
- The index template maps `mtime_after` as `date_optional_time` ([src] `wazuh-template.json`), so the indexer reads that naive string as **UTC**.
- On a manager not running in UTC, the indexed `mtime_after` is wrong by the manager's UTC offset. That is exactly the 5 h shift in the docs example (`12:50:38` vs alert `-0500`).

**Adapter rules.**
- Read `_source.syscheck.mtime_after`, never the indexer's `fields` value.
- Interpret it in the manager's time zone. Take that offset from the `timestamp` of the same alert, which carries a correct `%z` from the same process and the same TZ.
  - Edge case: a DST switch between the mtime and the alert. We accept it and record it as a limitation.
- The lab normally runs in UTC, so the lab results don't depend on this logic. Unit tests cover a non-UTC fixture.

[lab] Confirmed on 2026-10-29 with the manager set to Asia/Jakarta (UTC+7): the FIM alert had `timestamp` `2026-10-29T10:40:56.338+0700` and `mtime_after` `2026-10-29T10:40:56` (local time, no offset). The indexer stored `mtime_after` as `10:40:56.000Z`, 7 h later than the real `03:40:56Z`, while `timestamp` was stored correctly as `03:40:56.338Z`.

How a manager's time zone is actually set: Wazuh daemons run chrooted in `/var/ossec` and read `/var/ossec/etc/localtime` (a copy made at install). Setting the container's `TZ` env, or `/etc/localtime`, did not change the alert times. For the adapter this changes nothing: it takes the offset from `timestamp`, whatever sets it.

### 4.4 What FIM time proves

- The agent's own detection time is sent (`data.timestamp` = `last_event`, [src] `create_db.c`), but analysisd **drops it for file events**: it is only used for scan-start/end info ([src] `fim_process_scan_info`, `syscheck.c`). The only event time in the alert is the manager's `timestamp`.
- **realtime/whodata:** the write happened at most "transport + queue delay" before `timestamp`. It is a tight upper bound and independent of file metadata, so `touch -d` cannot move it. That makes it stronger against timestomping than mtime. It still compares the manager clock with the web server's log clock, so the existing `clock_skew_s` applies.
- **scheduled:** `timestamp` only says "changed sometime before this scan", up to 12 h earlier. Use it only as an upper bound. The anchor is the mtime, capped at low confidence.
- `changed_attributes == ["mtime"]` (only mtime changed) is a timestomp signal.

### 4.5 FIM inventory (current state)

- 4.14 has **no** `wazuh-states-fim-*` index; it first appears in 5.0.
- The current state is available from the server API, `GET /syscheck/{agent_id}` on port 55000 ([src] `api/api/spec/spec.yaml`).
- **Not used in M6:** events are enough. Roadmap: use it as a "current snapshot" when no manifest exists.

## 5. Indexer API

[doc] https://documentation.wazuh.com/4.14/user-manual/indexer-api/getting-started.html

- HTTPS on 9200 with basic auth (`curl -k -u user:pass https://host:9200/…`). JWT on-behalf-of tokens are also possible.
- **Pagination:** "Point in Time (PIT) with `search_after` is the preferred pagination method in OpenSearch". `from`/`size` is limited to 10,000 results ([doc] https://docs.opensearch.org/2.19/search-plugins/searching-data/paginate/). The adapter uses PIT + `search_after`, sorted by `timestamp` then `_id` (a stable tiebreak).
- **Security:**
  - TLS is verified against the lab `root-ca.pem`; `--insecure` is an explicit flag only.
  - Credentials come from the environment or a file, never from CLI args.
  - Use a dedicated **read-only** user with read on `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*` only ([doc] https://documentation.wazuh.com/4.14/user-manual/user-administration/rbac.html).
- **No network by default** (CLAUDE.md). The adapter only connects when `--wazuh-url` is given.

## 6. Adapter design (implemented in M6)

```
adapters/wazuh/
  schema_v4.py   # every 4.x field name and index pattern, in one place
  client.py      # PIT + search_after, bounded window, no retries that reorder
  pull.py        # `webforensics pull`: index checks, alerts-only fallback, writes a recording
  recording.py   # read/write a recording (JSONL of raw hits + query metadata)
  logs.py        # archive hit -> LogEvent (via the existing parser on full_log)
  fim.py         # FIM alert hits -> FileEvidence (+ findings outside the docroot)
  __init__.py    # WazuhRecordingSource: the LogSource + FileEvidenceSource for the core
```
Details that changed while building it are in D80.

**Two-step flow.** `pull` writes a recording, and `analyze --wazuh-recording` reads it offline.
- Only `pull` touches the network.
- Analysis of a recording is deterministic and reproducible, the same as with the FileAdapter.
- Unit tests and the benchmark use recordings, so CI never needs Wazuh (plan §5).
- The recording has a header with: Wazuh version, index patterns, time window, agent, query, pull time, and whether archives existed.

**Recording format.** One JSON object per line: `_index`, `_id` and `_source` as returned. Nothing is altered, so it is an evidence copy. Its SHA-256 goes into the report.

## 7. Gaps in our own engine that M6 must close (all closed; see D76–D80)

Found by checking the above against `models.py`, `correlate/seeds.py`, `correlate/anchor.py` and `correlate/gaps.py`.

1. **No file content from Wazuh.** FIM gives hashes, not bytes, so `content_ref` is `None`. The content rules (D28) and M7 code localization can't run.
   - What still works: FIM `added` maps to `BaselineStatus.NEW`, and a new code-like file is already a strong seed (`seeds.is_strong_seed`). So the root cause should still be found.
   - Option: `--webroot` provides content only. It is used only when its SHA-256 equals the FIM `sha256_after`. Without it, the report says "content analysis not performed".
2. **The core can't use FIM time.**
   - `choose_anchor` knows only btime > ctime > mtime.
   - `lonely_writes` ignores mtime-based anchors, so with Wazuh it would see nothing.
   - `FileEvidence` has no FIM fields, although `TimestampBasis.FIM` and `TimestampSource.WAZUH_FIM` exist.

   Proposed changes:
   - Add `fim_first_seen`, `fim_last_seen` and `fim_mode` to `FileEvidence`.
   - Add a FIM branch to `choose_anchor`. For realtime/whodata, the first `added` time is the anchor, capped at medium confidence (it is an upper bound and crosses two clocks). For scheduled, the mtime is the anchor, capped at low.
   - `lonely_writes` accepts realtime FIM anchors.
   - The FIM time is never written into `btime`/`ctime`.
3. **Deleted files.** `FileEvidence.sha256` is required. Deleted alerts carry the last hash (§4.2), so a deleted file becomes a `FileEvidence` with a new `deleted` flag. If no hash is present, it becomes a finding that cites the alert.
4. **Absolute paths.** FIM reports `/var/www/html/...`. A docroot-prefix config maps these to relative paths plus `url_paths` (the same map the FileAdapter uses). Paths outside the docroot become persistence findings; they are not dropped.
5. **Many events per file.** All events for one path build one `FileEvidence`. Every event stays a citation, so the timeline shows each change.
6. **Silence gaps in alerts-only mode.** Without archives, `gaps.py` would report "no log" for almost every minute, because normal requests are missing. In that mode the silence detector is off, and one explicit gap replaces it: `wazuh.alerts_only`.
7. **No line numbers.** Solved differently: citations point at the line of the recording that holds the raw log line (D80).

**M6 "done" test.** Unchanged: the same root cause and the same affected files via the WazuhAdapter (realtime FIM + archives) as via the FileAdapter. Citations and confidence may legitimately differ; the report shows why.

**Benchmark.** Each lab scenario gets `evidence/wazuh/recording.jsonl` next to the existing evidence. `eval` runs both adapters, and the results table gains an `adapter` column. Ground truth is unchanged.

## 8. Decisions (accepted 2026-10-29; full text in `decisions.md`)

- **D73: Wazuh 4.14.x, explicit `-4.x-` index names.** Latest 4.14 patch at install (D21). 5.x is unsupported and fails loudly. Why: 5.0 changes the index layout completely, and §1 shows the version can't be read from the indexer.
- **D74: Web events from `wazuh-archives-4.x-*`; alerts-only is a degraded mode.** Why: normal 2xx requests are level 0 and never alerted (§3.1). In degraded mode: one `wazuh.alerts_only` gap, silence detection off, confidence lowered.
- **D75: Re-parse `full_log` with our parser; Wazuh rule verdicts are not scored.** Why: the decoders lack time, UA and XFF (§3.2). One parser means both adapters behave the same.
- **D76: First-class FIM time in the core.** This covers the new `FileEvidence` FIM fields, the FIM anchor branch with caps by `syscheck.mode`, `lonely_writes` support, and `mtime_after` read in the manager TZ from the same alert's offset (§4.3, §4.4). Why: FIM time is the only write time Wazuh gives, and treating it as btime/ctime would overclaim.
- **D77: Content only from a hash-matched `--webroot`.** Why: Wazuh has no file bytes. Unverified content must not drive findings.
- **D78: Pull → recording → offline analysis.** Deleted files keep their last hash. Why: determinism, CI without Wazuh, and the recording acts as an evidence copy.

## 9. Change to plan.md (applied)

M6 row: "read web events from `wazuh-archives-*` (alerts-only as degraded mode) and FIM events from `wazuh-alerts-*`, via a recording" instead of "read web-log alerts from `wazuh-alerts-*`". Add the core changes from D76–D78 to the M6 scope.

**Schedule risk.** M6 is now an adapter *plus* core changes. If W5 slips, cut in this order:
1. deleted-file handling (keep it as a finding with a citation only);
2. the `--webroot` content option;
3. the alerts-only degraded mode (require archives instead).

The FIM anchor (D76) and recording (D78) are not cuttable. Without them, the done test can't pass deterministically.

## 10. [lab] checks (run 2026-10-28/29, Wazuh 4.14.9, branch `m6-wazuh-lab`)

Lab: manager + indexer from `wazuh-docker` v4.14.9 (dashboard off), agent container `wf-lab-agent` with the webroot and nginx logs mounted read-only, `TZ=UTC` everywhere. Scenario A was replayed three times in Wazuh mode; `lab/wazuh/smoke_check.py` ran last.

1. **Realtime FIM across containers: yes.** The agent logged `(6016): Directory set for real time monitoring: '/var/www/html'.` and `(6012): Real-time file integrity monitoring started.`. The PHP upload produced a rule 554 alert with `syscheck.mode=realtime` and `sha256_after` equal to the live file's SHA-256.
2. **`deleted` alerts carry `sha256_after`: yes.** The marker's `deleted` alert kept the last hash (same value as the `added` alert), as the source predicted (§4.2).
3. **FIM delay: under about 1.4 s.** The alert `timestamp` was 0.371 s after the upload request's log second (`22:49:07` vs `22:49:07.371`). The access log has 1 s resolution, so the delay is somewhere in 0.37–1.37 s. A realtime anchor window of a few seconds is enough.
4. **RAM: about 2.4 GiB total for Wazuh plus the lab** (indexer about 1.5 GiB with the default `-Xms1g -Xmx1g`, manager about 0.4 GiB, MySQL about 0.4 GiB, the rest under 20 MiB each). The 9.7 GiB VM has room; the earlier crash came from the dashboard plus host apps. With the unused manager modules off (below), the manager dropped to about 0.32 GiB.
5. **Read-only user: works.** `webforensics_reader` has index-level `read`, `indices:data/read/search`, `indices:data/read/point_in_time/create` and `.../delete` on `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*`, and no cluster permissions. Create and delete document both return 403. PIT create, two `search_after` pages and PIT delete all return 200.

Also confirmed:

- **Archives hold every web line, unchanged.** With `log_format` `syslog`, the 6 `full_log` strings in `wazuh-archives-4.x-*` matched the 6 lines of `access.log` byte for byte (as a multiset). This backs D74 and D75.
- **`mtime_after` has no offset** (`2026-10-28T22:49:07`), as §4.3 says. A one-off run with the manager in UTC+7 confirmed the 7 h shift in the index (details in §4.3).

New findings the adapter must handle:

- **Every re-enrollment gets a new `agent.id`** (001, 002, 003 for the same name `wf-lab-agent`, with `<auth><force>` enabled). Alerts from earlier IDs stay in the index. The adapter must select by agent name plus a time window, never by agent ID alone.
- **Vulnerability detection fills the disk.** It is on by default in 4.14 and downloads the CTI feed into the `wazuh_queue` volume (13 GB under `queue/vd` in this lab; the Docker Desktop disk image grew to 73.7 GB and does not shrink by itself). The project does not use it, so `setup.py` sets `<vulnerability-detection><enabled>no`. After that, all Wazuh and lab volumes total about 224 MB.
- **Unused manager modules are off.** The manager also monitors its own container: syscollector (inventory into `wazuh-states-inventory-*`, about 250 MB of queue within minutes), SCA, rootcheck and syscheck. None of it is lab evidence, and it adds alert noise. `setup.py` turns all of them off, as well as vulnerability detection (4.14 reference: "Disable the Syscollector wodle.", "Enables the module.", "Disables the execution of rootcheck.", "Indicates if the syscheck scan is disabled or not."). The manager log then shows "Module disabled" for each. Volumes stayed at about 229 MB over a full replay plus smoke check. The agent was already minimal (only FIM and logcollector).
- **Upstream compose uses `restart: always`,** so Wazuh started with every Docker Desktop launch and held about 2 GiB of RAM. The override sets `restart: "no"`; Wazuh runs only after `setup.py up`.
- **Old events stay indexed across replays.** Any "wait for event" or query must be bounded by time. The first version of the lab's FIM wait matched run 1's alert in later runs; it now filters by `agent.name` and `timestamp >= replay start`. `smoke_check.py` had the same flaw (its `deleted` wait matched an earlier smoke run's alert) and now uses the same filter.

End-to-end check of the adapter (2026-10-29), `tests/integration/test_wazuh_lab.py`:

- **All five scenarios agree.** Each scenario was replayed with Wazuh on; the FileAdapter evidence (logs + manifest) and a `pull` recording from that same run gave the same root-cause request, affected files and attacker IPs. Scenario E's forged mtime was caught through FIM: `added` at 04:27:53, then `modified` with `mtime_after` 2024-01-15.
- **A deploy inside the window looks like an attack.** The app's files are copied into the webroot right after the agent's baseline scan, so FIM sometimes reports all of them as `added` within 0.1 s. Before D79 all eight code files were reported as affected. Whether this happens depends on which container wins the race.
- **The agent restarts itself once after enrolling** (`auto_restart` defaults to yes; the agent got a new configuration from the manager). Scenario D's cache file was written at 04:33:17.26, between the agent stopping (04:33:15) and its new baseline scan (04:33:18), and never produced an alert. The lab agent now sets `<auto_restart>no</auto_restart>` (4.14 client reference: "Toggles on and off the automatic restart of agents when a new valid configuration is received from the manager"). In a real incident this blind spot cannot be detected from the alerts, so Wazuh reports state it (`limit.fim_blind_spots`).
- **Alerts-only, measured.** Pulling scenario E with the archives index treated as missing: none of the 7 access-log lines was an alert (all 2xx), only the PHP error-log line (rule 31301, level 3). The upload was still traced, through the error log, at low confidence and with the partial-log gap. This is D74 on real data. It also exposed D81: the error log's client was the edge proxy, which had been reported as the attacker.
- **Pull windows must start at the replay.** Back-to-back replays with a window that started 30 s early pulled the previous scenario's upload, which the adapter then correctly reported. Events stay indexed; the window decides what is evidence.

Resolved from source since the first draft: the meaning of `timestamp`, the archive event structure, the archive/alert `id` relation, the `mode` values, the `mtime_after` time zone, and the OpenSearch version and pagination method.

## 11. Trigger and write-back (M6+, checked 2026-11-01)

Same rules as above: [doc], [src] at `v4.14.9`, and [lab] for what was run on a live manager. The [lab] checks here used a throwaway `wazuh/wazuh-manager:4.14.9` container with no network (`--network none`) and only the files below added; no indexer and no agent.

**Integration (trigger).** [doc] https://documentation.wazuh.com/4.14/user-manual/manager/integration-with-external-apis.html
- A custom integration's `<name>` must start with `custom-`; the script with that name goes in `/var/ossec/integrations/`, owned `root:wazuh`, mode 750, first line naming the interpreter.
- Filters: `<level>`, `<rule_id>`, `<group>`, `<event_location>`; "when you combine `rule_id` and `group`, an alert must match both". So the FIM trigger and the web-attack trigger are two `<integration>` blocks with the same name.
- The script gets the alert file (JSON with `<alert_format>json`), the API key and the hook URL as its first three arguments.
- [lab] Two blocks with the same name are accepted: integratord logged "Enabling integration for: 'custom-webforensics'" twice and kept running.
- [lab] A file written into a realtime-monitored `/var/www/html` gave rule 554 (`syscheck.mode=realtime`) and integratord called the wrapper with `/tmp/custom-webforensics-<time>-<random>.alert`. An SQLi line appended to a monitored access log gave rule 31106 (level 6, "attack answered 200") and the same call. Both alerts, with the host name replaced, are the fixtures of `tests/unit/test_wazuh_trigger.py`.
- Wazuh 4.14's bundled Python is 3.10 without pydantic; webforensics needs 3.11+, so the wrapper runs it from its own virtual environment (`/opt/webforensics/venv`).

**Write-back.** [src] `integrations/virustotal.py`, `ruleset/rules/0490-virustotal_rules.xml`
- Results go to analysisd through the Unix datagram socket `<ossec dir>/queue/sockets/queue`, as `1:<location>:<json>`. The location is the integration name, or `[<id>] (<name>) <ip>-><integration>` to file it under an agent, with `|` doubled and `:` written `|:`.
- The JSON carries `"integration": "<name>"`; the rules match it after the built-in JSON decoder, with a level-0 parent rule and child rules on the fields.
- [lab] `wazuh-logtest` with `webforensics_rules.xml`: the scenario F events matched 100801 (level 12, summary with an entry point), 100804 (affected file) and 100805 (attacker IP), and scenario D's summary matched 100803 (level 3, no compromise). Field substitution in descriptions works (`$(webforensics.root_cause.path)` became `/admin/login.php`), and lists decode as arrays.
- [lab] `queue.py`, run by the manager's own Python 3.10, sent the same three events to the live socket; all three appeared in `alerts.json`. Events sent with an agent location were filed under that agent (`agent.name` `web01`, `agent.id` `001`); the one without went to the manager (`000`).

**Whole chain on the lab: passed (2026-11-01).** Lab manager and indexer from `setup.py up`, the integration installed as in [lab/wazuh/integration/README.md](../lab/wazuh/integration/README.md) (Python 3.11 from the Amazon Linux 2023 repository in a venv, wrapper, rules, the two `<integration>` blocks, the read-only `webforensics_reader` account), then scenario F replayed with `WF_LAB_WAZUH=1`:
- 12:26:00 UTC: the realtime FIM `added` alert for `/var/www/html/uploads/scenario-f-marker.php` (rule 554) started one worker. No other alert of the replay passed `decide`.
- 12:26:46: after the 45 s settle time, the worker had pulled the window from the indexer, analyzed it, written report.md/html/json, viewer.html and writeback.jsonl, and sent 3 events.
- The automatic report matches the scenario F ground truth: entry point `GET /admin/login.php`, SQL-injection login bypass (medium), affected file `uploads/scenario-f-marker.php`, attacker 172.30.0.1, cited as `recording.jsonl:6`.
- Rules 100801 (level 12), 100804 and 100805 raised alerts filed under `wf-lab-agent` (001), and all three were searchable in `wazuh-alerts-4.x-*` with the read-only account, so the dashboard shows them.
- The write-back alerts did not start a second analysis: `trigger.log` has one start and one finish.
- The integration runs as the `wazuh` user, which could read the config and password file (`root:wazuh`, 640) and write to the queue socket.

Found while running it: `lab/README.md`'s stop command left the profiled agent container running; it now includes `--profile wazuh`.
