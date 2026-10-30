# Benchmark v2

Benchmark v2 is reserved for replay evidence from vulnerable applications, public
background traffic, and real attack tools. The ground-truth format remains compatible
with the v1 schema; the schema adds a `deleted` file change, a file `role`, and an
optional advisory URL for vulnerable-code provenance.

The s01 pilot is recorded. It includes replay records, `ground_truth.json`, `notes.md`,
access/error logs, manifests, a defanged webroot snapshot, and `defanged.tsv`. Its full
webroot is encrypted outside Git. The pilot has not been scored with the webforensics
CLI.

The v2 replay and evidence workflow is under [`lab/v2`](../../lab/v2/README.md). See
[`SOURCES.md`](SOURCES.md) for the verified public sources and release candidates.

**Recording status:** s01 only. Scenarios s02–s12 have not been started. Treat s01 as a
pilot for review, not as a scored benchmark or a source of v2 accuracy numbers.

Defanging compares every captured file with the pristine baseline. New or changed files
are stubbed if their extension is executable, if they contain script openers, or if they
are ZIP/PHAR archives. This also stubs benign PHP files created by plugins; the encrypted
full capture retains their originals. Public POST log entries replay with empty bodies
because the source logs do not contain request bodies.
