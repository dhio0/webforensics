# Evaluation

`webforensics eval benchmark/` runs the analyzer on every scenario under
`benchmark/scenarios/` and compares the result with that scenario's `ground_truth.json`.
The analysis is the same one `analyze` does. The options a scenario needs (error log,
UTC offset, trusted proxies, baseline) come from its `analysis` block.

```
webforensics eval benchmark/ --markdown results.md --json results.json
webforensics eval benchmark/ --no-runtime     # deterministic table, e.g. for CI diffs
```

## Metrics

| Metric | Definition |
|---|---|
| Step recall | Attack steps whose log line is cited by any timeline event, out of the steps expected in the timeline. A step is expected unless its category is `benign_request` or it sets `expected_in_timeline: false`. |
| Root cause | `correct`: the reported root-cause event cites the ground-truth root step's line. `alternative`: that line is only among the alternative candidates (counted as not correct). `wrong`: another request. `missed`: no root cause reported. `false_root`: a root cause was reported for a scenario with no compromise. |
| False IPs / false files | Attacker IPs (IOCs) and affected files reported by the tool that are not in the ground truth. These are false accusations. |
| IP / file precision | Correct reports divided by all reports. `-` when nothing was reported. |
| Expected rules | Rule ids the scenario requires (for example `FILE-ANTIFORENSICS-TIMESTOMP` in E), found among the findings. |
| Code line | Vulnerable-line localization. Not measured until M7. |
| Runtime | Wall time of loading the evidence plus correlation. Machine-dependent, so it is left out with `--no-runtime`. |

A scenario counts as **fully correct** when the root cause is correct, no expected step,
file or rule is missed, and there are no false accusations.

## Splits

`dev` scenarios may be used while developing rules. `held_out` scenarios may not: a rule
change is never made because of a held-out result. Their numbers are summarized
separately, and they are the better estimate of how the tool does on attacks it was not
tuned on. When a held-out scenario fails, the failure is reported as it is.

## Limits of this benchmark (read before quoting numbers)

- **Self-made.** The same person wrote the lab, the attacks, the ground truth and the
  rules. That is a bias. Mitigations: scenarios D and E were written before the rules were
  tuned on them, E is held out, the replays are fixed scripts, and ground truth is
  written from what the replay did, never from the tool's output.
- **Small and synthetic.** A handful of scenarios on one lab app. Real traffic is
  messier (shared NAT addresses, CDNs, log rotation, many more file writes). Good
  numbers here show the method works on known cases, not that it works everywhere.
- **Step recall counts citations, not understanding.** A step is "found" when its line
  is cited somewhere in the timeline. Whether it is described correctly is checked by
  the golden reports and unit tests, not by this metric.
- **The lab markers are inert.** Content-based webshell rules are not exercised by the
  lab. They are covered by unit tests with defanged fixtures.

## Results history

Rule changes made because of a benchmark result are listed here, so the numbers can be
judged.

| When | Scenario | First result | Change |
|---|---|---|---|
| M5 | D (dev) | false root, admin IP and cache file blamed | D69: a request explained by another file's birth ranks lower |
| M5 | D (dev, re-recorded) | fully correct; its report did not say the bots' SQLi login bypass probably worked | D71: such a bypass is reported (not accused), with fixes |
| M5 | E (held-out) | fully correct on first run | none |
| M6 | all, re-recorded with Wazuh on | FileAdapter unchanged (fully correct); WazuhAdapter fully correct on first scoring | none to the scores. The lab test behind it found D79 (deploy batch accused), D81 (proxy accused from the error log) and the FIM restart blind spot |

M6 re-recorded every scenario in one replay with Wazuh on, so the file evidence and the
Wazuh recording come from the same run. What changed in the evidence, and why:
- A and F were from an older lab: client IP 172.19.0.1 and no X-Forwarded-For field. Now
  172.30.0.1 and the current log format; F's vulnerable line moved from 8 to 13 because
  `login.php` had changed since F was recorded (now the same file as in B).
- In Wazuh mode the lab truncates the logs before nginx starts, so nginx's
  `signal process started` notice is no longer line 1 of `error.log`; the upload's
  error-log line moved from line 2 to 1 in B, D and E.
- The steps were checked line by line against the new logs (`lab/wazuh/record_benchmark.py`
  prints each step next to its line), including D's concurrent requests.

## Code localization (M7)

The scenario table's **Code line** column scores the vulnerable line for SQL injection scenarios (B, F: correct for both adapters). Upload scenarios (A, E) show `n/a`: the tool does not localize upload flaws yet. Each scenario's `evidence/webroot/` holds the app's code, copied only where it hashes to the manifest.

Because the lab app and the hand-made fixtures come from the rule author, the localizer is also judged on real fixes (tests/fixtures/php_sqli/cve/, D83):

| Set | Cases | Result |
|---|---|---|
| Hand-made fixtures | 12 vulnerable, 10 safe | all correct; 1 documented limitation |
| Real CVE fixes (selection rule fixed before scoring) | 13 | **5 detected**, 2 on the exact line the fix changed; 0 findings in the 13 fixed files |

The 8 misses, by category:

| Category | Cases | Why |
|---|---|---|
| Input arrives through calls or object properties | CVE-2026-52770, CVE-2026-33770, CVE-2026-33723 | calls are not followed |
| Framework or application input API | CVE-2019-11512, CVE-2017-16558 (`\Input::post()`), CVE-2015-10018 (Yii), CVE-2025-62617 (app validator) | only superglobals are sources |
| Not SQL injection | CVE-2019-10913 | HTTP method override |

Read with care. "Detected" means a finding in the vulnerable file that the project's own fix removes; it was chosen after a first scoring (exact changed line only) gave 0/13, because fixes often change the line that reads the input rather than the line that builds the query (D83). 13 cases is a small sample, and the selection rule keeps only the brief's scope (superglobals reaching a query in one file), which excluded 162 of 175 real fixes. The localizer was improved on these cases (generic SQL sinks, branch-aware tracking, element-wise escaping), so they are a dev set now; M8 needs fresh cases to measure without that bias.

## Using the benchmark with another tool

See [benchmark/README.md](../benchmark/README.md). The ground truth format is tool-neutral.
