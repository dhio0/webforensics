# Evidence formats

## Webroot manifest v1 (`manifest.tsv`)

The manifest is written by `scripts/collect.sh` on the server. It records file metadata at acquisition time, because copying a webroot (zip, scp, Windows) destroys ctime and inode numbers, and often mtime (D9).

```
#webforensics-manifest v1                       ← required first line
#collector=collect.sh 0.1.0
#hostname=web01
#webroot=/var/www/html
#collected_at=1793072400                        ← epoch seconds, UTC
#utc_offset=+0700                               ← server local offset at collection
#birth_time_supported=0|1
#columns=path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256
<one tab-separated row per regular file or symlink>
```

| Column | Meaning |
|---|---|
| `path_hex` | Path relative to the webroot, as hex of the raw bytes. File names are attacker-controlled and may contain tabs, newlines or invalid UTF-8, so hex keeps the format unbreakable. |
| `type` | `f` (regular file) or `l` (symlink, never followed) |
| `size`, `uid`, `inode` | Integers from `stat` |
| `mode` | Octal permission bits (`stat %a`) |
| `atime`, `mtime`, `ctime` | Epoch seconds (`-` = unknown) |
| `btime` | Birth time in epoch seconds. `0` or `-` = unknown (filesystem or kernel doesn't report it). |
| `sha256` | Content hash. For symlinks, the hash of the link target string. `-` if the file was unreadable (the row is then rejected by the parser). |

Parser behavior:
- A wrong magic line or wrong columns makes the whole manifest unusable (fatal error).
- Bad rows are counted as rejected with a reason and never crash the run.
- Paths that are absolute or contain `.`/`..` segments are rejected (D15).
- Duplicate paths keep the first row.
- Unknown `#key=value` header lines are preserved in `header.extra`.

Known limitations of the collector:
- Timestamps have 1-second resolution.
- Hashing reads every file, which may update atime depending on mount options. Each file is stat'ed before it is hashed, so the recorded atime is the pre-collection value.
- Empty directories are not recorded.
- It spawns a few processes per file, which is fine for typical small sites but slow for very large webroots.

## Access logs

| `--log-format` | Layout | Timestamp means |
|---|---|---|
| `nginx_combined` (default) | `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"` | end of request (log write time) |
| `apache_combined` | `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"` | start of request |

- An optional extra trailing quoted field is read as X-Forwarded-For.
- The format must be given explicitly, because the two formats are indistinguishable from the text and only differ in timestamp meaning.
- `.gz` rotated files are read transparently. Line numbers refer to the decompressed content.
- Line numbers count every physical line, including blank ones, so a citation `access.log:42` matches what `sed -n 42p` shows.
- Invalid UTF-8 bytes are kept as `\xHH`, like nginx's own escaping.
- POST bodies are **not** in access logs. This is a fundamental limitation (see plan §4).

## Error logs (optional, supporting evidence)
`ErrorLogFileSource` reads nginx and Apache 2.4 error logs (optionally `.gz`).

```
nginx:  2026/10/27 17:00:10 [error] 31#31: *7 <message>, client: 203.0.113.7, server: _, request: "POST /admin/upload.php HTTP/1.1", ...
Apache: [Tue Oct 27 10:00:10.123456 2026] [php:warn] [pid 12] [client 203.0.113.7:51234] <message>
```

- Error-log timestamps have **no UTC offset**. Pass the server's offset (e.g. `+0700`, from the manifest's `#utc_offset`). The offset used is stored on each event and shown with every error-log citation.
- nginx entries include the request line, so they are matched to access-log lines by IP + method + path + time. Apache entries are matched by IP + time only.
- Lines that don't start an entry (PHP stack traces, wrapped messages) are counted as `not_entry_start` failures in `error_failures`. They are expected and do not create evidence gaps.

## Wazuh recording v1 (`webforensics pull`)
A JSONL file. Line 1 is the header; every other line is one indexer hit, with its values unchanged (keys sorted):
```
{"header": {"format": "webforensics-wazuh-recording/1", "agent": "web01",
  "since": "...", "until": "...", "pulled_at": "...", "tool_version": "...",
  "docroot": "/var/www/html", "access_logs": ["/var/log/nginx/access.log"],
  "error_logs": ["/var/log/nginx/error.log"], "archives": true,
  "web_index": "wazuh-archives-4.x-*", "fim_index": "wazuh-alerts-4.x-*",
  "counts": {"web": 7, "fim": 1}}}
{"stream": "web", "_index": "wazuh-archives-4.x-2026.10.29", "_id": "...", "_source": {...}}
{"stream": "fim", "_index": "wazuh-alerts-4.x-2026.10.29", "_id": "...", "_source": {...}}
```
- `web` hits: one log line each. The raw line is `_source.full_log`, `_source.location` says which file it came from (an `access_logs` or `error_logs` entry). With `"archives": false` they come from alerts, so most requests are missing.
- `fim` hits: FIM alerts (`_source.syscheck`: `path`, `event`, `mode`, `sha256_after`, `mtime_after`, ...). `mtime_after` is read in the time zone of the alert's `timestamp` (docs/wazuh-notes.md §4.3).
- Every query is bounded by `agent.name` and the time window; hits are in `timestamp`, `_id` order.
- Citations in the report point at line numbers of this file (`case01.jsonl:17`), and the report lists the file's SHA-256 under its inputs. Keep the recording with the case like any other evidence copy.
