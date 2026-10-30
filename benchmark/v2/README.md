# Benchmark v2

Benchmark v2 is reserved for replay evidence from vulnerable applications, public
background traffic, and real attack tools. The ground-truth format remains compatible
with the v1 schema; the schema adds a `deleted` file change, a file `role`, and an
optional advisory URL for vulnerable-code provenance.

Each recorded scenario belongs in `s01` through `s12` and must include its replay
records, `ground_truth.json`, `notes.md`, and `evidence/` (access/error logs, manifest,
defanged webroot snapshot, and `defanged.tsv`). Full webroots are encrypted outside
Git. No scenario should be scored with the webforensics CLI while v2 is being recorded.

The v2 replay and evidence workflow is under [`lab/v2`](../../lab/v2/README.md). See
[`SOURCES.md`](SOURCES.md) for the verified public sources and release candidates.

**Recording status:** scenario evidence and ground truth have not yet been recorded.
Do not treat this directory as a scored benchmark or cite v2 accuracy numbers.
