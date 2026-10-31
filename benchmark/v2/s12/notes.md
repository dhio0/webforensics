# s12 recording notes

s12 is a no-compromise WordPress 5.5.3 scenario. The administrator opens the
core update page, updates a local cache-plugin fixture from 1.0 to 1.1 through
WordPress's ZIP installer, uploads a small PNG to the media library, and warms
the plugin's PHP cache. A catch-all hook returns HTTP 200 for most missing
paths, including the scanner probe. The fixture source, local version pins,
and hashes are recorded in `SOURCES.md`.

The lab network is internal and has no external route. WordPress's official
core-update service therefore could not supply a package during recording.
The admin opened the core update page and received a real application response,
but no core update is claimed. The plugin update used a local, project-owned
fixture package, so it remained reproducible without outside access. This is
the scenario's offline adaptation.

All labeled requests are benign admin work or a scanner probe and are marked
outside the incident timeline. Labels use unique `X-Lab-Step` headers. The
media file was attached to the default Hello World post using WordPress's
authenticated media upload form. Ground-truth access-log lines are:

| Step | Access-log line | Result |
|---|---:|---|
| `admin_login_form` | 4,951 | HTTP 200; benign admin session |
| `admin_login` | 4,952 | HTTP 302; administrator session established |
| `core_update_check` | 4,953 | HTTP 200; core update page opened |
| `plugin_update_form` | 4,955 | HTTP 200; plugin package form opened |
| `plugin_update_package` | 4,956 | HTTP 200; local update package submitted |
| `plugin_update_apply` | 4,957 | HTTP 302; plugin updated |
| `cache_warm_form` | 4,958 | HTTP 200; cache controls opened |
| `cache_generation` | 4,959 | HTTP 200; benign PHP cache generated |
| `media_upload_form` | 4,960 | HTTP 200; media form opened |
| `media_upload` | 4,961 | HTTP 200; PNG uploaded |
| `scanner_catchall_probe` | 4,962 | HTTP 200; catch-all response |

The eleven named steps span 32.978%–33.051% of 15,013 access rows. There are
15,000 background rows, 10,384 client identities, and 903 User-Agents. The
largest client share is 0.973%; the largest User-Agent share is 4.407%. Visitor
2xx/3xx success is 98.220%. All 2,923 scanner rows are retained; 2,875 received
HTTP 200 from the catch-all, while the remaining scanner responses keep their
actual application status.

`root_cause_step` is null and `attacker_ips` is empty. Ground truth records the
updated cache plugin, generated PHP cache, and uploaded PNG as benign changes
with `expected_in_report: false`; the empty File Manager backup path is a
separate benign side effect. The collector defanged the changed plugin PHP,
cache PHP, and empty File Manager PHP path. It did not alter the PNG. Schema
validation, byte-identical label regeneration, zero-parse-failure evidence
validation, self-check, restoration of all 2,847 manifest entries, and the final
Defender scan passed. The scenario folder is 3,263,416 bytes including these
notes and scan record; Defender realtime protection was enabled and the scan
found zero detections. Isolation checks refused a non-allowlisted service and
confirmed external addresses were unreachable.
