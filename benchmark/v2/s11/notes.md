# s11 held-out recording notes

s11 is a no-compromise WordPress 5.5.3 scanner scenario. The pinned sqlmap
source (commit `c42ebd7acf47c88b6407995dd9842a2eb5d6534d`) tested the public
search parameter against the isolated site and exited successfully without
reporting an injectable parameter. Eight marked scanner requests probed login,
admin, XML-RPC, REST, plugin, and common configuration paths. No files were
changed by the scan; WordPress File Manager created an empty backup index as a
side effect, recorded with role `side_effect` and `expected_in_report: false`.

The labels for the eight named requests use unique `X-Lab-Step` headers. Their
lines are 5,851–5,858 in `access.log.gz`. The sqlmap phase is retained in the
access log and summarized in `replay/s11-scan.json`; it did not produce a
separate root-cause step because no compromise occurred. Ground truth therefore
has `root_cause_step: null` and no attacker IPs.

This is an offline adaptation of the originally described failed scan. The
scanner requests receive normal WordPress responses on some known routes
(HTTP 200, 302, and 405) and 404 on absent paths; no claim is made that every
probe failed with 4xx/5xx. Background traffic retains the same 15,000-row
Organization X/NASA pairing used by the development scenarios. There are
10,384 background client identities and 903 User-Agents; visitor success is
96.274%, and all 2,923 scanner rows remain. The eight named scanner requests
span 38.738%–38.784% of 15,104 access rows.

Schema validation, byte-identical ground-truth regeneration, zero-parse-failure
evidence validation, isolation checks, restore of all 2,844 manifest entries,
and Defender scan passed. Defender realtime protection was enabled and found
zero detections. The empty side effect is the sole defanged file.
