# Run 2: frozen tool on benchmark v2 (official held-out result)

Run 2 used the frozen analysis code (93d205b) and the scorer recorded in `PREREG.md`, on the benchmark at commit `aca8168` (rounds 7 and 8).

**Before the run:**
- The round-7 clean restores were re-checked file by file against the current manifests.
- Every file matched, except the defanged files, and each of those equals its committed stub.
- `--webroot-root` pointed at per-scenario junctions, so no scenario fell back to the partial webroot in the repository.

Raw output: [`run2.txt`](run2.txt), [`run2.json`](run2.json).

## Result

| Split | Fully correct | Step recall | Root cause correct | False accusations |
|---|---|---|---|---|
| dev (8) | 2/8 (run 1: 1/8) | 0.12 (run 1: 0.18) | 2/8 (run 1: 1/8) | 0 (run 1: 4) |
| held-out (4) | 1/4 (run 1: 1/4) | 0.83 (run 1: 0.83) | 1/4 (run 1: 1/4) | 0 (run 1: 0) |

- **Passed:**
  - s01: unauthenticated plugin upload with an agent;
  - s11: a failed scan, correctly not called a compromise;
  - s12: legitimate admin work, now correctly not called an attack.
- **Held-out failures (s02, s06, s09):** listed in `run2.txt` and **not examined**, so that no fix is tuned on them.

This is still a poor result, and it is kept as recorded. The tool makes no false accusations on v2 any more, but it misses most attacks.

## What changed from run 1, from the dev scenarios only

**The tool code is unchanged, so every difference comes from the benchmark.**

**s12 (benign admin work): now correct.**
- In run 1, the fast replay put about a hundred requests in each second.
- That made a plugin update and a cache page look attacker-created, and the administrator look like the attacker.
- At realistic pacing the tool no longer accuses them.

**s07 and s10 (attacks that install a plugin): from "wrong" or "partly found" to "missed".**
- In run 1, the files were found only because a background client happened to be linked to them, which was a false accusation produced by the replay speed.
- Now the attacker's plugin files appear under "changes to review manually", not as affected files.
- The tool sees the upload request, `POST /wp-admin/update.php?action=upload-plugin`, but does not read the query string, so it does not treat the request as an upload.
- This is tool weakness 1 from run 1. It was hidden by the replay artifact before.

**Dev step recall fell from 0.18 to 0.12, for the same reason:** s10's two partial steps in run 1 came from that accidental link.

## Tool weaknesses (fair to fix on dev)

The six weaknesses listed in `run1-analysis.md` all still apply. Run 2 adds one observation.

**Review list noise.**
- In s07 and s10, about 63 unchanged application files are listed as "changes to review". They include core WordPress files and theme stylesheets.
- Their manifest rows are identical to the baseline.
- Their ctimes come from the container install, about 40 seconds before the first log line.
- Two things contribute:
  1. the tool lists them even though they equal the baseline;
  2. the benchmark starts the log right after the install. On a real server, the install is long past.
- This does not change any score, but it buries the attacker's plugin among 63 harmless files.

## Benchmark notes

- The changes since run 1 are recorded in `../ROUND7.md`, `../ROUND8.md` and the README "Known limits":
  - realistic pacing;
  - no visitor POSTs to static files;
  - the portable restore;
  - the s07 side-effect fix;
  - background clients in `198.18.0.0/15`.
- **Runtime:** analysis took 2 to 98 s per scenario. The time comes from antivirus scanning of the restored trees on first read, not from analysis.
