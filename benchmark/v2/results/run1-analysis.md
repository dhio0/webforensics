# Run 1: frozen tool on benchmark v2

Run 1 used the frozen analysis code (93d205b) and the scorer recorded in `PREREG.md`. The webroots were restored outside the repository and checked file by file against each manifest.

Raw output: [`run1.txt`](run1.txt), [`run1.json`](run1.json).

## Result

| Split | Fully correct | Step recall | Root cause correct | False accusations |
|---|---|---|---|---|
| dev (8) | 1/8 | 0.18 | 1/8 | 4 |
| held-out (4) | 1/4 | 0.83 | 1/4 | 0 |

Scenarios that passed: s01 (plugin upload with an agent) and s11 (failed scan, correctly not called a compromise).

This is a poor result. It is kept as recorded.

## Why, from the dev scenarios only

The held-out failures are listed in `run1.txt` and were not examined, so that no fix is tuned on them.

### Benchmark artifacts (they make the task harder than a real small site)

1. **Replay speed.** Each scenario replays 15,000 background requests in about two minutes: 104–129 requests per second on average, up to 196 in one second. The whole s07 attack, from brute force to plugin activation, falls within 3 seconds.
   - The access log has one-second resolution, so a file's timestamp matches about a hundred requests.
   - In s07, 849 write-capable requests fall within the 120 s creation window.
   - A small organization's site, which is what this tool targets, sees a few requests per second at most.
2. **Visitor POSTs to static files.** The visitor remapping keeps the source method, so background clients POST to CSS and JS files (`/wp-content/themes/.../index.js`, `/print.css`).
   - Real browsers do not do this.
   - These requests become write candidates.
3. **Payload only in the POST body.** Combined logs have no request bodies.
   - In s03 (time-delay SQL injection in Save News) and s05 (command injection), the exploit line reads like an ordinary form POST.
   - s03 also creates no file, so nothing in its evidence separates the exploit from normal editing.
   - This is realistic. It is a limit of access-log evidence, not a scoring error.

### Tool weaknesses (fair to fix on dev)

1. **Upload hint matches on folder names.** A POST to `/wp-content/themes/.../index.js` counts as upload-like, because the path contains `theme`. The real `POST /wp-admin/update.php?action=upload-plugin` counts only as possible, because the query string is not read. In s07 this put a background client at the root cause.
2. **Apache multi-extension names.** `images/category-1-.php..` (s04) is not treated as executable, because its last suffix is `.`. Apache with `AddHandler` runs any name with a `.php` part.
3. **A handler configured by `.htaccess`.** s10 installs an `.htaccess` that runs `.jpg` files as PHP. The tool reports the `.htaccess` but not the `.jpg` agent beside it.
4. **Files changed by authenticated admin work.** In s12, a legitimate plugin update and a generated PHP cache page are reported as attacker files, and the administrator as the attacker.
5. **Deleted agent driven by POST bodies.** In s08 the agent was removed before collection, and its commands were in POST bodies. Log-only detection (D85) needs a visible command parameter or response-size variation, so nothing was found.
6. **New non-script files.** In s05 the command injection wrote a `.txt` marker into the upload folder. The tool does not consider non-executable new files.

### Restore and environment notes

- The images that `restore_webroot.py` needs were missing locally for 8 of 11 scenarios. They were local image IDs, not registry digests.
- Codex's earlier restore trees were used instead, after checking every file hash against the current manifests.
- Antivirus scanning of freshly copied trees made the first load of some scenarios take about 100 s. Analysis itself takes about 6 s per scenario.
