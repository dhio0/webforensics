# s01: unauthenticated WordPress File Manager upload - round 7

## Application and verified story

WordPress 5.5.3 and WordPress File Manager 6.0 reproduce CVE-2020-25213.
The exposed connector accepts an unauthenticated upload; the uploaded agent then
returns results for three identification commands inside the isolated lab. The
[NVD advisory](https://nvd.nist.gov/vuln/detail/CVE-2020-25213) and pinned sources
are recorded in `../SOURCES.md`. The scenario story and ground-truth meaning are
unchanged. No payload or agent contents are included in these notes.

## Live timing and labels

The recording ran once, uninterrupted, from 2026-11-01 06:48:41.916 UTC to
08:01:41.563 UTC (13:48-15:01 WIB). No part was resumed or stitched. Access-log
seconds span 4,379 seconds: 15,000 background requests, 17 actor requests, and
one ordinary WordPress scheduled self-request. The whole-log average is 3.42955
requests/second; both the background and overall busiest second have 20 requests.
Source inter-arrival times were scaled with a rolling burst cap, preserving quiet
periods and bursts. Evidence timestamps and file timestamps were recorded live.

Seed 5031 selects the background trigger at 41% of the source stream. All actor
requests occupy 40.97%-52.52% of the completed log. First reconnaissance to last
agent exchange takes 365 seconds. Human action starts are seeded and at least
46.79 seconds apart. Weevely's internal handshake and command exchanges retain
their native speed; those exchanges explain the short bursts within each command.

| Step | Access line | Expected in incident timeline |
|---|---:|---|
| Site check | 6153 | No |
| Plugin version check | 6682 | No |
| Administration probe | 7098 | No |
| XML-RPC probe | 7276 | No |
| Unauthenticated upload, root cause | 7372 | Yes |
| Agent identity | 7394 | Yes |
| Agent working directory | 7535 | Yes |
| Agent account | 7886 | Yes |

`label.py` alone generates the ground truth. Ordered access/sidecar joins verify
requests, status, client, and timestamp. Agent labels use the actual invocation
start/end window and select the first matching exchange as command initiation;
later exchanges remain unlabelled. The upload root cause is actor-sourced and 2xx.
The app crawl and setup finished before incident logging was cleared and started.

## Background and method routing

The accepted Organization X request stream and NASA identity mapping are retained:
12,077 visitors, 2,923 scanner requests, 10,384 background clients, and 903 source
user agents. The largest non-actor client contributes 0.98% of all requests; the
largest overall user-agent share is 4.40%. Visitor answers are 99.942% 2xx/3xx.
The repeated nested-path share is 0.027%. The background container address never
appears in the evidence.

Visitor POSTs use exact crawled form actions, including their routing queries:
661 comment-form requests, 419 login requests, and 210 password-recovery requests.
There are zero background writes to static assets. One retained source scanner
probe disguises an API endpoint with a semicolon and JavaScript suffix; it is
reported separately in the self-check, rather than treated as a browser asset.
Scanner paths stay unchanged. GET/HEAD query remapping, empty source POST bodies,
and source-anonymized browser versions remain as accepted in round 6. Source
browser-version values that look like IP addresses were not corrected or invented.
The final user agents contain no forbidden lab/crawler labels.

## Files and portable restore

The agent and the plugin's empty backup index are defanged. The backup index is
a plugin side effect with `expected_in_report: false`. Within five seconds either
side of each file's recorded ctime, there is one POST/PUT candidate for the agent
and two for the backup index. These counts are observations, not selection limits.
The original full capture remains encrypted outside Git.

Restore uses the public digest-pinned WordPress tree and SHA-256-pinned plugin
archive in `lab/v2/portable-inputs.json`; the local recording image is provenance
only. The install overlay has inert stubs for `.htaccess`, `wp-config-sample.php`,
and secret `wp-config.php`, with reasons and original hashes/sizes in `defanged.tsv`.
The two changed executable artifacts are also stubs. No live attacker file reached
Windows. `restore_webroot.py s01 DEST` needs no local credentials or app image.

The first clean proof removed three local app images and verified all 2,845 entries
in a new empty external destination. A second proof with the historical-ID sweep
found the app images absent and verified another new destination. Both proofs are
recorded in `replay/restore-validation.txt`. The completed tree is checked again
for every hash/stub and exact file name, including Windows path handling.

## Analyst read and checks

I read all 1,736 entries in access lines 6153-7888 using a lossless row view with
complete request and user-agent dictionaries, and read all 17 actor lines raw.
After collection I verified that this window's timestamp, client, request, status,
size, and referrer fields were unchanged. I then read all 50 final background
lines selected with seed 7001. Their exact numbers and final access-log hash are
bound by `replay/analyst-review.json`.

I checked form-versus-asset methods, plausible status/body-size combinations,
client and user-agent variety, quiet periods and bursts, nested paths, the whole
reconnaissance/upload/agent sequence, and native agent handshakes. The preserved
source query strings and anonymized version numbers were treated as source-data
characteristics. No additional recording defect was found in this review.

Schema validation, byte-identical ground-truth regeneration, step joins, parser
checks, defanging, size, clean-image restore, and Defender all pass. Access,
manifest, and error parse failures are zero; Defender detections are zero. No v2
analysis/evaluation was run, and no Defender exclusion was added. Attempt 1 was
thrown away after a form-query routing defect; only this fresh attempt supplies
these artifacts. Detailed values are in `replay/self-check.txt`.
