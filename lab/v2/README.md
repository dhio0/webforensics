# M8 benchmark v2 lab

## Current state

All twelve v2 scenarios are recorded on the `m8-benchmark-v2` branch. The dev
split is s01, s03, s04, s05, s07, s08, s10, and s12; the held-out split is s02,
s06, s09, and s11. Scenario-specific adaptations and provenance are recorded in
`benchmark/v2/README.md`, `HELDOUT.md`, and `STATUS.md`. Recording validation
does not run the analysis or evaluation commands.

## Isolation and setup contract

The Compose stack puts vulnerable apps and attackers on an `internal: true` network,
exposes only the edge on `127.0.0.1`, and selects one app upstream with `APP_UPSTREAM`
for each run. Each request is served at `/`, so access-log paths match the app's paths.
The edge accepts lab-only client-IP and step headers, but forwards a fixed set of
ordinary HTTP headers only; `proxy_pass_request_headers off` drops every incoming
`X-Lab-*` header before a request reaches an app. Attack tools accept only allowlisted
lab service names. Images and build inputs are pinned and recorded in `SOURCES.md`.

Copy `.env.example` to `.env`, set local-only credentials, and generate a 32-byte key
encoded as 64 hex characters. Keep `.env` out of Git. Compose should bind the configured
Windows `FULL_EVIDENCE_DIR` to `/full-evidence` inside the collector container and mount
the scenario output at `/capture`.

## Logs and labels

`nginx/templates/default.conf.template` writes the evidence access log as nginx
combined format with only the optional trailing quoted X-Forwarded-For field. It writes a separate JSON sidecar to
`benchmark/v2/<id>/replay/labels.log`, outside `evidence/`. The sidecar includes the
request id and step header. `label.py` joins both logs in write order and verifies each
request, status, client IP, and timestamp within 1.1 seconds. It fails on mismatches or
different row counts. This supports repeated identical requests in linear time.
Header-capable steps use a unique `X-Lab-Step`; Weevely and Hydra steps use the scenario
script's attacker-IP/time-window record plus a request/status discriminator. Labels
never enter the evidence access log, and no tool output is consumed.

## Collection and defanging

`collect.py` invokes the existing `scripts/collect.sh` inside the app container. A
pristine baseline capture supplies `baseline.tsv`; each final capture retains the
collector's v1 manifest, including mode, inode, ctime, btime, original hash, and size.
Defanging compares current files to that baseline, independent of replay file lists.
Every new or changed executable extension (including `.htaccess`, `.user.ini`, `.inc`,
`.pht`, and `.phps`), file containing `<?` or `<%`, ZIP, or PHAR is replaced by a plain
text `DEFANGED <original sha256> <original size>` stub. This also stubs benign PHP cache
and update files; the encrypted full capture retains their original contents. Roles are
recorded in `defanged.tsv`. A post-write scan fails if a changed snapshot file still
contains `<?php` or `<?=`.

The original `collect.sh` tar is gzip-compressed and encrypted with AES-256-GCM using
the pinned `cryptography` package and a random 12-byte nonce stored in the file header.
Only the encrypted archive goes to `FULL_EVIDENCE_DIR`; raw webroot files remain inside
the container. `decrypt.py s01` authenticates the archive and extracts regular files
only into a folder beneath `FULL_EVIDENCE_DIR`. It rejects traversal, links, special
files, and any output path inside the repository. Before decrypting, add the temporary
Defender exclusion to the external full-evidence directory yourself if needed; this
workflow never adds exclusions.

## Background replay

`BackgroundReplay.start()` starts a joinable worker thread so a scenario runner can
interleave background traffic with the attack. It keeps input order, uses a fixed pace,
logs UTC start/end times and connection-failure counts, and writes a first-seen IP map
to `replay/ip_map.tsv`. Mapped clients use RFC 5737 documentation pools first, then a
private `10.0.0.0/8` pool, excluding attacker and lab ranges; distinct source addresses
always receive distinct mapped addresses. POST records replay with empty bodies because
public access logs do not contain request bodies. NASA traces have no user-agent field;
the replay labels that field as unavailable.

The scenario runner starts this thread concurrently with the attack. `--service` checks
the allowlisted app selected for the run; Compose configures the edge upstream, and
background request paths stay rooted at `/` without an app prefix. Background source
downloads and image pulls finish before the isolated network is started.

After a scenario is captured, run `python lab/v2/validate_evidence.py
benchmark/v2/s01/evidence` to load its access log and manifest with the existing
`LogFileSource` and `ManifestFileSource`. The command prints event/file totals and
parse-failure counts, and exits nonzero if any parser reports a failure.
