# Held-out scenarios

The four held-out IDs are s02, s06, s09, and s11. No v2 scenario was scored before this round. Evidence or ground-truth changes listed here came from Claude's pre-scoring review (round 6).

| ID | Ground-truth SHA-256 | Original recording commit | Round 6 commit / change |
|---|---|---|---|
| s02 | `d7ac3c02f0de620bed382caeb3930fd92c9eda4edfe6cc8c8dc508403d9a413c` | `ead8215b91c9f367f879051c4f7f3cdfa979024a` | `5ff2319`; SQLmap User-Agent normalized in evidence; ground truth unchanged. |
| s06 | `2719dda470be507574b2f4a004e85151ece9829dd8daf12a451871812d76e327` | `b983dee74e31cde58398aa74dc483f5c5916aba2` | `0595d50`; successful local file read is the root cause and expected timeline step; no code execution or write is claimed. |
| s09 | `85c6374f9de51f39758e194f6c0faa0fec3713a7d533d0db8fdb0cbc1d1e4500` | `cd8786e489a6a401ac947e0864be87c9439e1b34` | `5ff2319`; timestomp User-Agent normalized in evidence; ground truth unchanged. |
| s11 | `b83497717db1ca3713400f0b6016fa4e42622e8dd081b3536b7ed53ad9ed4287` | `aff8cbf7dd4de3b153fe04693ccbe49f75e23bc6` | `0595d50`; scanner address is named as the actor; still no compromise and no root cause. |

Recording order differed from the listed order: s11 was recorded first among held-outs, then s02, s06, and s09. The scenario notes document the observed behavior and limits.
