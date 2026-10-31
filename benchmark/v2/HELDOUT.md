# Held-out scenarios

The four held-out IDs are the IDs selected in the task plan before their recording: s02, s06, s09, and s11. No rule changes were tuned from their results. They are listed here with the committed ground-truth hash and recording commit.

| ID | Ground-truth SHA-256 | Recording commit | Notes / adaptation |
|---|---|---|---|
| s02 | `d7ac3c02f0de620bed382caeb3930fd92c9eda4edfe6cc8c8dc508403d9a413c` | `ead8215b91c9f367f879051c4f7f3cdfa979024a` | DVWA requires authentication for its SQLi module; sqlmap confirmed injection but did not produce a user-table dump. The root cause is the later upload. |
| s06 | `83863843daa1c18bfd5df5800265fa6ec3c535a03755e226746598d1a50f8eaf` | `b983dee74e31cde58398aa74dc483f5c5916aba2` | Verified LFI read only; log/session poisoning and RCE were not verified. |
| s09 | `85c6374f9de51f39758e194f6c0faa0fec3713a7d533d0db8fdb0cbc1d1e4500` | `cd8786e489a6a401ac947e0864be87c9439e1b34` | Weevely timestomp through the standard authenticated plugin installer; no installer CVE is claimed. |
| s11 | `f2819fcc1e050473c793b85eafd7e44ed68bffe53514ed522ad12dd9fff5dbbb` | `aff8cbf7dd4de3b153fe04693ccbe49f75e23bc6` | Failed sqlmap/scanner run; known WordPress paths returned some normal responses instead of only errors. |

Recording order differed from the listed order: s11 was recorded first among held-outs, then s02, s06, and s09. The scenario notes document the observed behavior and limits.
