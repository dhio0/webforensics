# Run 3: the tool after the M9 dev fixes

Run 3 used the M9 fixes (D94), built from the eight dev scenarios only, on the same benchmark, scorer and webroots as run 2. The rules were written in `PREREG.md` before the run.

Raw output: [`run3.txt`](run3.txt), [`run3.json`](run3.json).

## Result

| Split | Fully correct | Step recall | Root cause correct | False accusations |
|---|---|---|---|---|
| dev (8) | 6/8 (run 2: 2/8) | 0.91 (run 2: 0.12) | 6/8 (run 2: 2/8) | 0 (run 2: 0) |
| held-out (4) | 2/4 (run 2: 1/4) | 0.83 (run 2: 0.83) | 2/4 (run 2: 1/4) | 0 (run 2: 0) |

**Held-out is the number that counts.** The dev gain is expected, because the fixes were made by reading those scenarios.
- Held-out went from 1/4 to 2/4: s02 is now fully correct, and s09's root cause moved from "wrong" to "alternative".
- s06 is still missed.
- Their reports were not read, so nothing here explains why. They stay untouched for a later run.

## Dev scenarios

| Scenario | Run 2 | Run 3 | What changed |
|---|---|---|---|
| s01 | correct | correct | unchanged |
| s03 | missed | missed | SQL injection in a POST body that writes no file. A file-first tool has nothing to start from. |
| s04 | missed | correct | `.php..` counts as a script. |
| s05 | missed | correct | Command injection rule, an attacked endpoint that then writes, a non-code file written by the attacker. |
| s07 | missed | alternative | All 7 steps and both files found. The tool names the brute-forced login (Hydra) as the way in and lists the upload as the alternative; the ground truth names the upload. This was stated before the run. |
| s08 | missed | correct | A deleted agent driven through POST bodies is reported as a script seen only in the logs. |
| s10 | missed | correct | The query string makes the plugin upload an upload; a clean login is not the way in; an image answered like a script is a script. |
| s12 | correct | correct | Still no accusation. |

## Read with care

- **The dev numbers are post-hoc.** Each fix is a general rule with a synthetic test, but these scenarios shaped them.
- **s12 passes partly by luck of the app.** WordPress writes an overwrite through a second GET. An administrator installing a *new* plugin after a clean login would look like s10 in an access log, and the tool would report it.
- **s10's `.htaccess` rule was not exercised on v2.** The `.htaccess` is defanged in the public evidence, so the image was caught by its response size instead.
- **Run 3 was checked for regressions on cases outside v2** before it was run:
  - lab benchmark v1, both adapters: unchanged;
  - the three earlier DFIR cases: same accusations and root causes as D89;
  - the fourth real case at scale: no accusation.
- **The Organization X check found one false accusation, which was fixed before run 3.** It came from the first version of the POST-driven script rule: scanner probes through a shared proxy address (D94).
- **Runtime:** 2 to 94 s per scenario. The time is mostly antivirus scanning of the restored trees, not analysis.
