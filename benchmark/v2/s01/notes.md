# s01 pilot notes

## Scenario and verification

This pilot uses CVE-2020-25213 in WordPress File Manager 6.0 on WordPress 5.5.3 with
the Apache/PHP image recorded in `SOURCES.md`. NVD describes the vulnerable exposed
elFinder connector and unauthenticated upload/execution behavior:
[NVD CVE-2020-25213](https://nvd.nist.gov/vuln/detail/CVE-2020-25213). In the internal
Docker lab, the unauthenticated upload returned a success response, the uploaded file
was served from the plugin's file directory, and the pinned Weevely 4.0.3 agent returned
results for three commands. The Windows host received only the defanged webroot and the
authenticated encrypted full capture. No Contact Form 7 test was run; CVE-2020-35489 is
not used by this scenario.

## How each step line was found

`label.py` joined the edge's ordinary combined access log with the separate ordered
sidecar and checked request, status, client, and timestamp for every pair. The root
cause upload used the unique `X-Lab-Step` value recorded by the scenario runner. Weevely
cannot add that header, so each command record stores the attacker address, the HTTP
request and status, and a narrow 30 ms interval near the end of that single command's
own recorded execution window. Each interval identifies exactly one matching request.

| Step | Access log line | How it was selected |
|---|---:|---|
| Unauthenticated plugin file upload (root cause) | 28 | Unique sidecar step label |
| Weevely identity command | 71 | Attacker address, request, status, recorded time window |
| Weevely working-directory command | 100 | Attacker address, request, status, recorded time window |
| Weevely user command | 128 | Attacker address, request, status, recorded time window |

The replay runner attempted 5,000 background requests from 5,000 log lines; all 5,000
appear in the evidence access log. The access log also contains 13 attacker requests and
3 requests originating from the WordPress container during startup. The application
requests are not background traffic or attack steps.

## Changed files and defanging

The baseline comparison found two new PHP paths: the uploaded agent and an empty plugin
backup index. Both appear in `evidence/manifest.tsv` with their original metadata and
hashes, and both are represented by inert `DEFANGED` stubs in `evidence/webroot/`.
`evidence/defanged.tsv` records the original hashes, sizes, roles, and reasons. The
manifest loader reports two expected content-hash mismatches because the safe stubs
intentionally differ from the original files; its manifest syntax parse failures are
zero. Access-log and error-log parse failures are zero.

The captured `error.log` is empty because this run emitted no nginx errors; it was
created fresh for this pilot after the interrupted-run leftovers were deleted.

The encrypted capture is outside the repository at the local full-evidence path from
`lab/v2/.env`. It uses AES-256-GCM. No Defender exclusions were added.
