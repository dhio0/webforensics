# s02 held-out recording notes

s02 is an offline adaptation using the GPL-3.0 DVWA training app at pinned
commit `a1978a2fed195acd093010af6395f86a281537ca`. DVWA's SQL injection module
requires an authenticated session, so the preconfigured local administrator
account was used before the sqlmap run. Pinned sqlmap confirmed the `id` query
parameter is injectable, then attempted a user-table dump. It exited zero but
produced no `users.csv`; the run metadata records `user_table_dump_confirmed: false`.
No administrator hash dump is claimed. This diverges from the planned order and
from the original SQLi-to-login chain.

The same administrator session uploaded a Weevely agent to DVWA's upload area,
and a single identity check confirmed execution. The upload is the root-cause
step because the SQLi occurred after login and did not supply the credentials.
The agent was defanged before evidence reached the host. The root-cause upload
is line 10,591; the SQLi phase's first candidate line is 10,354; administrator
login is line 10,351. Lines were selected from the isolated request labels and
the replay records, not from analysis output.

The 15,000 background rows use the same Organization X request shapes and NASA
client identity pairing. This capture has 15,247 total access rows, 10,384
background client identities, 903 User-Agents, a 93.475% visitor success share,
and 2,923 retained scanner rows. The named attack steps span 67.889%–69.463%
of the log. The collector defanged one PHP agent file.

DVWA is a deliberately vulnerable training application and this scenario makes
no separate CVE claim. Schema validation, byte-identical regeneration,
zero-parse-failure evidence validation, self-check, baseline-based defanging,
restoration of the complete manifest, isolation checks, and Defender scan
passed. Defender realtime protection was enabled and found zero detections.
