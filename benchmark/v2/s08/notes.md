# s08 recording notes

s08 is the log-only scenario: WordPress 5.5.3 with WordPress File Manager 6.0
accepts an unauthenticated agent upload, the attacker uses it for short checks,
and the agent is deleted before the collector takes its final snapshot. The
File Manager version and CVE-2020-25213 advisory are documented in
`SOURCES.md`. The agent is generated and stored only in the isolated attacker
container. Its SHA-256 and size are recorded in `replay/transient-file.json`;
the file content is not committed or included in the Windows evidence tree.

The named upload and reconnaissance steps use unique `X-Lab-Step` headers.
Weevely commands and the self-removal operation are selected by attacker IP,
tool time window, request path, status, and first candidate ordinal. The final
request checks that the removed path returns 404. Ground-truth access-log lines
are:

| Step | Access-log line | Result |
|---|---:|---|
| `site_check` | 10,351 | HTTP 200; reconnaissance |
| `plugin_version_check` | 10,352 | HTTP 200; reconnaissance |
| `admin_probe` | 10,353 | HTTP 302; reconnaissance |
| `xmlrpc_probe` | 10,354 | HTTP 200; reconnaissance |
| `unauthenticated_file_upload` | 10,355 | HTTP 200; root cause |
| `agent_identity` | 10,356 | HTTP 200; agent use |
| `agent_working_directory` | 10,362 | HTTP 200; agent use |
| `agent_user` | 10,365 | HTTP 200; agent use |
| `agent_deleted` | 10,368 | HTTP 200; agent self-removal |
| `agent_absent_check` | 10,371 | HTTP 404; confirms deletion |

The named steps span 68.910%–69.043% of 15,021 access rows. The 15,000
background rows have 10,384 client identities and 903 User-Agents. The largest
client share is 0.973%; the largest User-Agent share is 4.407%. Visitor
2xx/3xx success is 96.274%, and all 2,923 scanner rows are retained.

The deleted agent's recorded hash is
`b8635cdb968e3fff9a282d75fdbfdb0fb3d32918a19d3ed2d5caaa3cbe51ffb2` and its
size was 514 bytes. Because it did not exist in either the baseline or final
webroot, `label.py` now carries an explicit deleted-file record from replay
metadata into ground truth. This keeps the scenario log-only while preserving
the expected file history. The collector also found the empty
`wp-content/uploads/wp-file-manager-pro/fm_backup/index.php` File Manager side
effect; it is marked `expected_in_report: false` and defanged.

Schema validation, byte-identical label regeneration, zero-parse-failure
evidence validation, self-check, restore of all 2,844 manifest entries, and
Defender scan passed. The scenario folder is 3,250,508 bytes;
Defender realtime protection was enabled and the scan found zero detections.
