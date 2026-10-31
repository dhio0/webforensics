# s09 held-out recording notes

s09 tests timestamp manipulation with WordPress 5.5.3 and the pinned Weevely3
agent. An authenticated administrator installed a local fixture archive with
the agent. The agent's pinned `file_touch` module changed its modification time
to 2001-01-01 and verified that time through the same agent. The module
implementation and supported timestamp inputs are in the [pinned Weevely
source](https://github.com/epinna/weevely3/blob/3d62e889871a62a344365b6a2d02b35c5ac1e946/src/weevely/modules/file/touch.py).

The marked archive upload is line 9,905. The timestamp operation is line 9,912
and is the root-cause step. The administrator login and installer form are at
lines 9,902–9,903. Weevely does not send `X-Lab-Step`, so the timestamp request
was selected by the attacker's IP, the command's recorded UTC time window, its
request path, status, and ordinal. No payload or agent code is reproduced here.

This uses the normal authenticated WordPress plugin installer and therefore
makes no CVE claim. It adapts the planned timestomp technique without a separate
WordPress vulnerability. The collector defanged the plugin PHP, agent PHP, and
empty File Manager backup side effect; the side effect is `expected_in_report:
false`. The scenario has 15,000 background rows and 15,016 access rows total,
10,384 clients and 903 User-Agents, 96.274% visitor success, and all 2,923
scanner rows. Named steps span 65.943%–66.010% of the log.

Schema validation, byte-identical regeneration, zero-parse-failure evidence
validation, self-check, isolation checks, manifest restoration, and Defender
scan passed. Defender realtime protection was enabled and found zero detections.
