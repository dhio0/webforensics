# Held-out scenarios

The four held-out IDs are s02, s06, s09, and s11. The round-7 recordings preserve the accepted stories, split and ground-truth meaning; the analysis code stayed frozen. Historical round-6 changes are retained below.

| ID | Ground-truth SHA-256 | Original recording commit | Round 6 commit / change |
|---|---|---|---|
| s02 | `d7ac3c02f0de620bed382caeb3930fd92c9eda4edfe6cc8c8dc508403d9a413c` | `ead8215b91c9f367f879051c4f7f3cdfa979024a` | `5ff2319`; SQLmap User-Agent normalized in evidence; ground truth unchanged. |
| s06 | `2719dda470be507574b2f4a004e85151ece9829dd8daf12a451871812d76e327` | `b983dee74e31cde58398aa74dc483f5c5916aba2` | `0595d50`; successful local file read is the root cause and expected timeline step; no code execution or write is claimed. |
| s09 | `85c6374f9de51f39758e194f6c0faa0fec3713a7d533d0db8fdb0cbc1d1e4500` | `cd8786e489a6a401ac947e0864be87c9439e1b34` | `5ff2319`; timestomp User-Agent normalized in evidence; ground truth unchanged. |
| s11 | `b83497717db1ca3713400f0b6016fa4e42622e8dd081b3536b7ed53ad9ed4287` | `aff8cbf7dd4de3b153fe04693ccbe49f75e23bc6` | `0595d50`; scanner address is named as the actor; still no compromise and no root cause. |

Recording order differed from the listed order: s11 was recorded first among held-outs, then s02, s06, and s09. The scenario notes document the observed behavior and limits.

## Round 7 replacements

re-recorded in round 7 because of a replay-speed artifact; the analysis code stayed frozen

| ID | Ground-truth SHA-256 | Round 7 recording commit |
|---|---|---|
| s02 | `ae3903050ffbd03e7f72fb3dc1b2a897f302b2d06b517b96b9e2f2215d257525` | `cff266070feb5edf0805676d1feaf7671649994d` |
| s06 | `2985a2f356736b985aed1e7723eb365294c01c5ae374b03ea920f2a967e90121` | `22c9a333a10dbecf6225e3ecc49872ff8d7a47bd` |
| s09 | `671cd2a275938df75344de4f54482c78ee51ada24814c417096dc23645cc9484` | `4f190e153115db0031b21e046ebb5433e739958b` |
| s11 | `f93c41e1eacdf7887f4b7199ed6a39e9f7a67534dadb53ec356caccb7ecd7971` | `371d603f829b0f5ff9a76f835a31e793d7d354ef` |

The s11 configuration spelling was corrected from `heldout` to schema-valid `held_out`, and its ground truth regenerated with `label.py`; its no-compromise meaning is unchanged. Every replacement has a completed analyst read, an uninterrupted live replay, a clean Defender scan, and a portable restore proof after local app-image removal.

## Round 8 evidence correction

The held-out ground-truth meaning is unchanged; evidence logs changed only by the approved background address remap. Current access-log SHA-256 values:

| ID | Access-log SHA-256 |
|---|---|
| s02 | `ebb9c26f22dbd9abb99b5bba1a5bf4ba624db6c7d060b93fbe4dd8938ae8599e` |
| s06 | `594a4ac89cb11af16eb35d9d27fc6a3d37927fb15599db573825c4d4f8bf95f4` |
| s09 | `8731fcd3d044c47f00e6f3a1e8d6aaef54c0022a89a445a3d31f76b2ef02c956` |
| s11 | `2b5d1a0e799d65b6f3a4b0aebbd477bd96b676b9955a02ce16bf3b20f24001be` |
