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

## Using the benchmark with another tool

See [benchmark/README.md](../benchmark/README.md). The ground truth format is tool-neutral.
