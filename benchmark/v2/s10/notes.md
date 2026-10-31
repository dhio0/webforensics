# s10 recording notes

s10 exercises persistence through Apache configuration in the isolated WordPress
5.5.3 lab. A WordPress administrator installs a ZIP plugin package containing an
`.htaccess` rule and a Weevely agent named with a `.jpg` extension. The agent then
returns the result of a short identity check, proving the server handled the image
extension as PHP. The WordPress and Weevely pins are recorded in `SOURCES.md`.
This uses WordPress's normal authenticated plugin ZIP installer, so no CVE is
claimed for the installer.

The package and generated agent exist only in the attacker container during the
replay. The collector defanged every changed executable or script-bearing file:
the `.htaccess` configuration, plugin PHP file, image-extension agent, and the
empty File Manager backup side effect. No live code is stored in the committed
webroot. The captured agent output is not stored.

Reconnaissance and form/login/upload requests are labeled with unique
`X-Lab-Step` headers. The agent check is selected by attacker IP, time window,
request path, status, and first candidate ordinal. Ground-truth access-log lines
are:

| Step | Access-log line | Result |
|---|---:|---|
| `site_check` | 9,601 | HTTP 200; reconnaissance |
| `login_page_probe` | 9,602 | HTTP 200; reconnaissance |
| `admin_probe` | 9,603 | HTTP 302; reconnaissance |
| `plugin_upload_probe` | 9,604 | HTTP 302; reconnaissance |
| `login_form` | 9,605 | HTTP 200; session cookie established |
| `editor_login` | 9,606 | HTTP 302; administrator session established |
| `plugin_upload_form` | 9,607 | HTTP 200; ZIP upload form opened |
| `persistence_upload` | 9,609 | HTTP 200; root cause |
| `image_agent_command` | 9,610 | HTTP 200; command check through `.jpg` |

The named steps span 63.938%–63.998% of 15,016 access rows. The 15,000
background rows have 10,384 client identities and 903 User-Agents. The largest
client share is 0.973%; the largest User-Agent share is 4.407%. Visitor
2xx/3xx success is 96.274%, and all 2,923 scanner rows are retained.

Schema validation, byte-identical label regeneration, zero-parse-failure
evidence validation, self-check, restoration of all 2,847 manifest entries,
and Defender scan passed. The scenario folder is 3,249,869 bytes. Defender
realtime protection was enabled and the scan found zero
detections.
