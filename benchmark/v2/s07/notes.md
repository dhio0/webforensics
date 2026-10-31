# s07 recording notes

s07 uses WordPress 5.5.3 and the pinned Hydra build to exercise a password-guessing
login followed by administrator plugin installation. The WordPress image and Hydra
source pins are in `SOURCES.md`. WordPress has no CVE claim in this scenario: the
tested second stage is its normal authenticated ZIP plugin installer, which is part
of the requested story ([WordPress 5.5.3 upload handler](https://github.com/WordPress/WordPress/blob/5.5.3/wp-admin/update.php)).

Hydra tried four local candidates in a fixed order and confirmed the lab administrator
account. Its output stored for replay has no password value. The attacker then signed
in, uploaded and activated a small plugin, and checked its plain-text marker. To keep
the evidence safe to store, the plugin only writes that marker; it does not provide a
command channel or webshell. The captured plugin PHP file is defanged. The replay does
not store the lab password or any live attacker file.

The named step labels use unique `X-Lab-Step` values except `hydra_valid_login`,
which selects the sole HTTP 302 POST during the recorded Hydra run window. Hydra
sends HTTP/1.0 for these requests. Ground-truth access-log lines are:

| Step | Access-log line | Result |
|---|---:|---|
| `site_check` | 7,351 | HTTP 200; reconnaissance |
| `login_page_probe` | 7,352 | HTTP 200; reconnaissance |
| `admin_area_probe` | 7,353 | HTTP 302; reconnaissance |
| `plugin_upload_probe` | 7,354 | HTTP 302; reconnaissance |
| `hydra_valid_login` | 7,362 | HTTP 302; valid password found |
| `login_form` | 7,365 | HTTP 200; login cookie established |
| `editor_login` | 7,366 | HTTP 302; administrator session established |
| `plugin_upload_form` | 7,367 | HTTP 200; upload form opened |
| `plugin_upload` | 7,368 | HTTP 200; root cause |
| `plugin_activation` | 7,370 | HTTP 302; plugin activated |
| `marker_check` | 7,371 | HTTP 200; marker read back |

The named steps span 48.935%–49.068% of 15,022 access rows. There are 15,000
background rows, 10,384 client identities, and 903 User-Agents. The largest client
share is 0.973%; the largest User-Agent share is 4.407%. Visitor 2xx/3xx success is
96.274%, and all 2,923 scanner rows are retained.

The collector found the uploaded plugin and its text marker. It also found the empty
`wp-content/uploads/wp-file-manager-pro/fm_backup/index.php` artifact from the already
installed File Manager plugin; that side effect is recorded with `expected_in_report:
false`. Both executable PHP paths were defanged. Schema validation, byte-identical
label regeneration, zero-parse-failure evidence validation, self-check, restoration
of all 2,846 manifest entries, and Defender scan passed. The scenario folder is
3,250,339 bytes; Defender realtime protection was enabled and the
scan found zero detections.
