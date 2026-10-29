# Web-incident forensics benchmark

Small, reproducible scenarios of a compromised (or not compromised) PHP website, each with
the evidence an analyst would get and a machine-readable answer key. The scenarios come
from an isolated local lab (`lab/`) that replays fixed request sequences, so the ground
truth is known exactly.

## Scenarios

| Id | Split | What happens | What it tests |
|---|---|---|---|
| A | dev | A GET SQLi probe (distractor), then an unauthenticated upload of a marker and a request to it | Root cause is the upload, not the louder probe |
| B | dev | Failed POST login, benign visitors, POST-body SQLi login bypass, authenticated upload | Root cause when the payload is not in the log (POST body), behind a proxy |
| D | dev | Busy site: ten visitors, two SQLi bots (one "logs in"), an admin uploading a photo, a CMS writing a `.php` cache file, a crawler. Nothing is compromised | False accusations: no root cause, no attacker IP, no affected file |
| E | held-out | Unauthenticated upload, then the marker's mtime is forged with `touch -d` (outside HTTP) | Root cause and the timestomp rule when mtime lies |
| F | dev | GET SQLi login bypass, then an authenticated upload | SQLi bypass as the root cause, not the upload |

There is no scenario C: the plan's original "direct upload" scenario was merged into A.
B, D and E go through a loopback edge proxy (`X-Forwarded-For`, trusted proxy in their
`analysis` block); A and F were recorded before it existed.

## Layout

```
scenarios/<id>/
  ground_truth.json      # the answer key (schema: schema/ground_truth.schema.json)
  evidence/
    access.log           # nginx combined (+ optional trailing "$http_x_forwarded_for")
    error.log            # optional, nginx error log
    manifest.tsv         # webroot manifest from scripts/collect.sh (see docs/evidence-format.md)
    baseline.tsv         # optional, manifest taken before any traffic
    webroot/             # optional, the app's code; each file hashes to its manifest entry
    wazuh/recording.jsonl  # optional, Wazuh web events + FIM alerts from the same replay
                           # (format: docs/evidence-format.md, "Wazuh recording v1")
```
A recording holds the same requests as `access.log`/`error.log`, with Wazuh's metadata.
Its web events carry the raw line in `_source.full_log`, so a tool scored on the recording
can be matched to the ground truth's `log_file`/`line_no` by that text.

## Ground truth

| Field | Meaning |
|---|---|
| `attacker_ips` | Client addresses that belong to the attacker. Empty when nothing was compromised. |
| `steps` | Requests of interest, in order, each pointing at `log_file` + `line_no`. `expected_in_timeline` says whether a correct timeline should cite it (default: everything except `benign_request`). |
| `root_cause_step` | The step that made the compromise possible, or `null`. |
| `files` | Files the attack created or modified, with their SHA-256 from the manifest. |
| `expected_rule_ids` | Optional: detections a correct analysis must report. |
| `split` | `dev` or `held_out` (never tune on held-out). |
| `analysis` | How to analyze the folder: which logs, error-log UTC offset, trusted proxies, baseline. |
| `vulnerable_code` | Optional: file, line and `vuln_class` of the vulnerable code in the lab app, plus the SHA-256 of that file as it was when the evidence was collected (it must match the scenario's manifest). `eval` scores the line only for classes the tool localizes (`sql_injection`). |

## Scoring your own tool

The answer key does not depend on webforensics. To score another tool, run it on the
`evidence/` folder and compare its output with `ground_truth.json` using the definitions
in [docs/evaluation.md](../docs/evaluation.md): step recall over the cited log lines, root
cause by log line, and false accusations as reported IPs or files not in the key.
For webforensics itself: `webforensics eval benchmark/`.

## Safety

The uploaded "webshells" are inert text markers with PHP-like names. Nothing in the
evidence is executable. Never run or `include` evidence files.

## External cases

`external/` holds cases built by others, scored against an answer key written before the
tool ran. The evidence itself is not redistributed; each case's README says where to get
it and how to reproduce the score. So far: `ashemery-case1` (Ali Hadi's "Web Server Case").
