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
