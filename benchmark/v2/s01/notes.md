# s01: unauthenticated WordPress File Manager upload

## Application and verification

This scenario uses WordPress 5.5.3 with WordPress File Manager 6.0 and CVE-2020-25213.
The [NVD advisory](https://nvd.nist.gov/vuln/detail/CVE-2020-25213) describes the exposed
elFinder connector and unauthenticated upload and execution path. In the isolated lab,
the upload succeeded, the uploaded file ran under Apache/PHP, and the pinned Weevely
agent returned results for three identification commands. No attack request or agent
contents are included here.

The app image is pinned by the digest in `replay/restore.json`. The full original capture
is encrypted outside Git under the directory configured by `lab/v2/.env`.

## Request phases and line labels

The attacker first checked the site and plugin version, then made two routine probes.
These four recon lines are labelled but have `expected_in_timeline: false`. The app crawl
ran before access-log collection; its six requests are excluded from the evidence and label
sidecar. Seed `5031` selected a 54% attack start; the upload began at 54.00% of the
completed access log. Three agent requests followed it.

| Step | Access line | Expected in timeline |
|---|---:|---|
| Site check | 8104 | No |
| Plugin version check | 8105 | No |
| Admin probe | 8106 | No |
| XML-RPC probe | 8107 | No |
| Unauthenticated upload (root cause) | 8108 | Yes |
| Agent identity | 8113 | Yes |
| Agent working directory | 8117 | Yes |
| Agent user | 8120 | Yes |

`label.py` joins the ordered sidecar and combined access log and verifies every pair's
request, status, client address, and timestamp. The sidecar uses the lab step header for
the four recon requests and upload. Each agent command uses the attacker address, exact
request and status, and a narrow recorded time window. The identity command generated
two identical agent requests in its window; its record selects the first request as the
command initiation, while later polling requests remain unlabelled.

## Background traffic

Visitor request methods, source targets, response patterns, and User-Agent strings come
from Organization X in the [MIT-licensed Zenodo log dataset](https://zenodo.org/records/20001206).
The source anonymizes almost every client address to one value, so the preparation step
pairs the chronological Organization X request rows with evenly sampled NASA KSC source
client identities. NASA's trace is used only for client identity; its missing User-Agent
field is never filled with an invented visitor agent. The selected stream has 903 distinct
User-Agent strings and 10,384 client identities; the most common agent is 4.41% and the
largest client share is 0.98%.

The deterministic classifier retains scanner User-Agents and source-side 404s with their
original paths. A single protocol-relative scanner path was normalized to an internal
origin-form path so the target allowlist could reject network authorities. For visitor
rows the preparer frequency-ranks source paths and maps them to the pre-attack crawl of
this app, while preserving method, query string, protocol, client, User-Agent, and line
order. App targets include pages, REST URLs, login, search, and discovered assets. Source
request bodies are unavailable, so POST requests replay empty.

The replay contains 15,000 background requests: 12,077 visitors and 2,923 scanner
requests. Visitor responses were 10,671 HTTP 200, 740 HTTP 301, 216 HTTP 302, 71 HTTP
400, 48 HTTP 401, 290 HTTP 404, and 41 HTTP 405. This is 96.27% 2xx/3xx. Scanner
responses were 2,264 HTTP 404, 642 HTTP 200, 9 HTTP 302, 7 HTTP 301, and 1 HTTP 403.
`replay/source-preparation.json` and `replay/background.json` preserve the source and
transformation counts. The attack lines span 53.973%â€“54.080% of the 15,026-line access log.
The replay ran in its own container at `192.0.2.135`; simulated client addresses are the
first field in `access.log.gz`. The background container address does not occur in that
evidence log. `replay/background.json` records the classification rule and counts.

## Changed files and side effect

The baseline was collected after plugin activation. Immediately before the baseline, the
empty `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php` was removed. It
reappeared as an empty file after the upload request, confirming that the upload flow
creates it as a plugin side effect. Its ground-truth role is `side_effect`, with
`expected_in_report: false`. The uploaded agent is the other changed file. Both are
represented by inert `DEFANGED` stubs, and `defanged.tsv` preserves their original hashes.

Only new or changed files are stored under `evidence/webroot`. Run
`python lab/v2/restore_webroot.py s01 DEST` outside the repository to restore the rest
from the pinned image and validate all manifest hashes before scoring.

## Evidence checks

- The attacker container could not reach an external address; a non-allowlisted service
  name was refused.
- The access log is ordinary combined format with the simulated client address first and
  no trailing X-Forwarded-For field. Access and sidecar rows join with zero mismatches.
- The Apache error log was collected as `evidence/app-error.log`; it has no entries for
  this run. `ground_truth.json` records Apache format and UTC offset `+0000`.
- The manifest and access-log adapters report zero parse failures; two expected hash
  mismatches correspond to the defanged stubs.
- The full restore command checked all manifest entries outside the repository.
- The encrypted full capture is stored outside Git. No live attacker file was copied to
  the host without defanging.
- No `webforensics analyze` or `webforensics eval` command was run.
