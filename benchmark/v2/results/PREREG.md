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
