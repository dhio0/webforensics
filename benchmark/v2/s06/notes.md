# s06 held-out recording notes

s06 adapts the intended local-file-inclusion scenario to a verified read-only
exercise in DVWA at pinned commit `a1978a2fed195acd093010af6395f86a281537ca`
(GPL-3.0-or-later). After using the lab's training account, the attacker
requests the DVWA file-inclusion page and confirms that it returns `/etc/passwd`
from the isolated container. The marked read is line 4,505; the preceding login
step is line 4,502. Both labels are derived from unique request headers.

The planned log/session poisoning path to code execution is not claimed. In this
container image, Apache access logs are collected through the container runtime,
and no repeatable writable log or session-file include path was verified. The
scenario therefore tests local-file inclusion and is an expected miss for RCE;
it creates no attacker file, has `root_cause_step: null`, and makes no CVE claim.

The log has 15,005 rows, including 15,000 background requests. The background
contains 10,384 client identities, 903 User-Agents, a 93.467% visitor success
share, and 2,923 scanner rows. Named steps are at 30.003%–30.023% of the log.
No file was defanged. Schema validation, byte-identical regeneration, evidence
parsing, self-check, isolation checks, full-manifest restoration, and Defender
scan passed; Defender realtime protection was enabled and found zero detections.
