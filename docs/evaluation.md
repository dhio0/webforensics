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

## First independent case (M8)

Ali Hadi's public "Web Server Case" (Windows, XAMPP, DVWA, browser and sqlmap) is the
first incident the author did not build. The answer key was written from a public
write-up before the tool ran, and its hash is recorded
([benchmark/external/ashemery-case1](../benchmark/external/ashemery-case1/README.md)).
The image itself is not redistributed.

| | Run 1: committed tool, unchanged | Run 2: after D84, D85 (post-hoc) |
|---|---|---|
| Attacker files flagged | 5/5 | 5/5 |
| Files falsely accused | 10 | 0 |
| Attacker IP (14 other clients in the log) | correct, no false IP | same |
| Attack events cited | 7/8 | 7/8 |
| Root cause: strict / lenient | wrong / correct | wrong / correct |
| Deleted attacker scripts reported | 0/4 | 4/4 |
| Vulnerable SQLi line | missed | found (2 accepted lines) |
| Markdown report | 1.8 MB | 60 KB |

What run 1 taught (each became a general fix with its own synthetic test, D84, D85):
- **Windows webroots.** URLs and file names differ in case. NTFS birth times are
  settable and survive unpacking, so an unpacked webshell was dated two years early.
- **Installs look odd.** App code in a folder named `upload`, encoded test data and old
  mtimes from unpacking made 10 install files look like webshells.
- **Deleted webshells.** sqlmap's shells were written by `INTO OUTFILE`, used and
  deleted. The file-first engine never saw them, so it named a later upload as the way in.
- **Includes.** The SQL query lives in a file the endpoint includes through a variable path.
- **Readability.** One timeline row per sqlmap request made the report unusable.

Read with care: one case, and run 2 was measured on the case the fixes came from. The
lab benchmark scores did not change. The strict root cause (a command injection in a POST
body) is out of reach for any access-log analysis. A second, untouched case is the next
step before claiming the fixes generalize.

### Second case, held out

Ali Hadi's Linux "Compromised Web Server" (Ubuntu, Drupal 7.26, Metasploit Drupalgeddon2)
was scored with the tool frozen after case 1, and an answer key written before the
evidence was opened ([benchmark/external/ashemery-linux1](../benchmark/external/ashemery-linux1/README.md)).

| | Run 1: frozen tool (held out) | Run 2: after D86 (post-hoc) |
|---|---|---|
| Attacker file found, no invented HTTP writer | yes | yes |
| Files / IPs falsely accused | 2 / 1 | 0 / 0 |
| Exploit request in the timeline | missed | found |
| Root cause, strict / lenient | wrong / wrong | correct / correct |

The held-out run is the number to quote, and it was poor: the case-1 fixes did not cover
code injection, a shell written from a root shell, or a form POST near an app install.
Two cases, two different sets of failures: the next case will likely find more.

### Third case, held out

The BND Forensik-Challenge (2016): a defaced Debian web server whose access log the
attacker cut ([benchmark/external/bnd-2016](../benchmark/external/bnd-2016/README.md)).

| | Run 1: frozen tool (held out) | Run 2: after D87 (post-hoc) |
|---|---|---|
| Compromise reported | no | yes |
| Defaced page flagged | missed | found |
| Gap over the exploit window | missed | reported |
| Root cause | none (correct: the exploit line was deleted) | none |
| False files / IPs | 0 / 0 | 0 / 0 |

### Fourth case, held out, real scale

Real logs of two Indonesian public-sector servers (Zenodo 20001206): 213,205 and 7,426,129
access-log lines, no webroot ([benchmark/external/id-public-sector-2025](../benchmark/external/id-public-sector-2025/README.md)).

| | Run 1: frozen tool (held out) | Run 2: after D88 (post-hoc) |
|---|---|---|
| Org X: verdict / false accusations | no compromise (correct) / 0 | same |
| Org Y: one run over 7.4M lines | did not fit in 16 GB RAM | completed: 3.7 min, 6.0 GB; one false file from merging sites (`/1514.php`), gone after D89 |
| Org Y: CyberPanel incident | missed (predicted in the answer key) | missed |
| Org Y: other compromise | a webshell found in the logs of one site (labelled `remote_code` by the dataset) | same |
| Org Y: true false accusations | 0 | 0 |
| Org Y: report size, all sites | 52 MB | 268 KB |

### Held-out record so far

| Case | Frozen at | Held-out result |
|---|---|---|
| Ali Hadi Linux web server | 3c05308 | webshell found; exploit missed; wrong root cause; 1 false IP, 2 false files |
| BND 2016 | 7bb44e3 | compromise missed entirely ("nothing suspicious"); no false accusations |
| Indonesian public sector (real scale) | 2ad5d68 | no false accusations in 7.6M lines; one webshell found; the admin-panel incident missed; one run did not fit in memory; one report 51 MB |

Four real cases, four different sets of failures, each fixed only afterwards. That is
the state of the tool: careful about false accusations, but not yet able to rely on for
cases unlike those it has seen.

## Using the benchmark with another tool

See [benchmark/README.md](../benchmark/README.md). The ground truth format is tool-neutral.
