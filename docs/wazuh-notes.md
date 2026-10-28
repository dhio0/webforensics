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

### 4.3 The `mtime_after` time zone bug (resolved from source)

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
- The lab runs with `TZ=UTC`, so the lab results don't depend on this logic. Unit tests cover a non-UTC fixture.

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

## 6. Adapter design (proposal, no code yet)

```
adapters/wazuh/
  schema_v4.py   # every 4.x field name and index pattern, in one place
  client.py      # PIT + search_after, bounded window, no retries that reorder
  recording.py   # read/write a recording (JSONL of raw hits + query metadata)
  logs.py        # archive hit -> LogEvent (via the existing parser on full_log)
  fim.py         # FIM alert hits -> FileEvidence (+ findings for deleted/outside-docroot)
```

**Two-step flow.** `pull` writes a recording, and `analyze --wazuh-recording` reads it offline.
- Only `pull` touches the network.
- Analysis of a recording is deterministic and reproducible, the same as with the FileAdapter.
- Unit tests and the benchmark use recordings, so CI never needs Wazuh (plan §5).
- The recording has a header with: Wazuh version, index patterns, time window, agent, query, pull time, and whether archives existed.

**Recording format.** One JSON object per line: `_index`, `_id` and `_source` as returned. Nothing is altered, so it is an evidence copy. Its SHA-256 goes into the report.

## 7. Gaps in our own engine that M6 must close

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
7. **No line numbers.** The report text says the line number is not available.

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

## 10. Open [lab] checks (first thing after install)

1. Realtime FIM in the agent container sees writes by the PHP container (§2).
2. `deleted` alerts carry `sha256_after` in practice (§4.2).
3. The FIM delay between write and alert `timestamp` in the lab. This sizes the realtime anchor window.
4. RAM headroom with the full lab plus Wazuh (VM now has 9.7 GiB).
5. Read-only indexer user: create a role with exactly these permissions and confirm that PIT works with it. PIT needs its own permission.

Resolved from source since the first draft: the meaning of `timestamp`, the archive event structure, the archive/alert `id` relation, the `mode` values, the `mtime_after` time zone, and the OpenSearch version and pagination method.
