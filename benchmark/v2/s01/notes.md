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
These four recon lines are labelled but have `expected_in_timeline: false`. Seed `5031`
selected a 54% attack start; the upload began at 54.00% of the completed access log.
Three agent requests followed it.

| Step | Access line | Expected in timeline |
|---|---:|---|
| Site check | 8110 | No |
| Plugin version check | 8111 | No |
| Admin probe | 8112 | No |
| XML-RPC probe | 8113 | No |
| Unauthenticated upload (root cause) | 8114 | Yes |
| Agent identity | 8120 | Yes |
| Agent working directory | 8123 | Yes |
| Agent user | 8126 | Yes |

`label.py` joins the ordered sidecar and combined access log and verifies every pair's
request, status, client address, and timestamp. The sidecar uses the lab step header for
the four recon requests and upload; each agent command uses the attacker address, exact
request and status, and a narrow recorded time window.

## Background traffic

The source is the [NASA KSC HTTP trace](https://ita.ee.lbl.gov/html/contrib/NASA-HTTP.html),
which has no User-Agent field. The deterministic preparation step therefore uses a fixed
browser User-Agent for visitor rows. It identifies scanner traffic by the source status
pattern (404) and keeps those source paths. It frequency-ranks the remaining paths and
maps them to the pre-attack crawl of the app, including pages, REST URLs, login, search,
and discovered assets.

The replay contains 15,000 background requests: 14,919 visitors and 81 scanner requests.
The visitor responses were 13,383 HTTP 200, 984 HTTP 301, 168 HTTP 302, and 384 HTTP
404. The retained scanner mix was 81 HTTP 404.
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
