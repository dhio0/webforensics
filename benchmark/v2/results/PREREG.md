# Pre-registration (written before any v2 run)

- Tool commit (analysis code frozen): 93d205bb4b989ec5029617c635fa37fa04143ca2 (main)
- Tool tree outside the scorer: unchanged on this branch (git diff 93d205b -- src, excluding evaluate.py and cli.py eval option)
- Scorer sha256 (src/webforensics/evaluate.py): 68fe037286bd3666c816d15cf5ece2ff322298019f44223135189765d767561d
- Recorded at: 2026-11-01T02:40:51Z

## Run 2 (written before run 2)

- **Benchmark:** rounds 7 and 8 at commit `aca8168b7eb504927b0e2218a9d22de34f1d1128`.
  - The scenarios were re-recorded with realistic pacing, method-aware POSTs and a portable restore.
  - The s07 side-effect file is no longer required.
  - Background clients were remapped to `198.18.0.0/15`.
- **Tool:** the analysis code is unchanged from 93d205b. `git diff 93d205b HEAD -- src` touches only `evaluate.py` and the `cli.py` `--webroot-root` option.
- **Scorer:** sha256 is unchanged, `68fe037286bd3666c816d15cf5ece2ff322298019f44223135189765d767561d`.
- **Webroots:** the round-7 clean restores listed in `restore-all-round7.json`, re-checked file by file against the current manifests before the run.
- **No tool change between run 1 and run 2.** Run 2 is the official held-out result. Held-out failures are listed but not examined.
- Recorded at: 2026-11-02T19:48:29Z

## Run 3 (written before run 3)

- **Benchmark:** unchanged since run 2 (`benchmark/v2` as of `aca8168`, merged into main at `e459250`).
- **Tool:** the M9 fixes (D94) on branch `m9-dev-fixes`, based on main `8fce4f2`. They are not committed yet: sha256 of `git diff main -- src` in the working tree is `399dfd8eec8b6120e5c128530b7bd0d83e0320ceac9c9c69a5ae86c0e049ee11`, 10 files, 532 lines added. The commit that records them will carry the same `src` content.
- **What the fixes were built from:** the eight dev scenarios only (s01, s03, s04, s05, s07, s08, s10, s12), read after run 2. The held-out failures of runs 1 and 2 (s02, s06, s09) were not examined; only their one-line summaries in `run1.txt` and `run2.txt` were seen.
- **Scorer:** sha256 is unchanged, `68fe037286bd3666c816d15cf5ece2ff322298019f44223135189765d767561d`.
- **Webroots:** the same round-7 restores and junctions as run 2.
- **Known before the run (dev, from the diagnosis runs):** s07's root cause will not be "correct". The tool names the brute-forced login and lists the plugin upload as the alternative (D94), while the ground truth names the upload. s03 is expected to stay missed.
- **Reporting:** run 3 is reported whatever it shows, held-out included. It is the first held-out number after tuning on dev; the held-out scenarios were scored twice before, but their failures were never read.
- Recorded at: 2026-11-03T06:46:52Z
