# s04 recording notes

s04 uses phpMyFAQ 3.2.5 and the authenticated category-image upload flaw,
CVE-2024-28105. The maintainer advisory identifies `CategoryImage.php` lines
66, 85, and 124 and describes how the uploaded content type and language value
combine to save a PHP file. The vulnerable source is recorded from the pinned
3.2.5 application image: `phpmyfaq/src/phpMyFAQ/Category/CategoryImage.php`,
line 124, SHA-256 `6574d0456a975bb018aca1f09f6e7f3ca9daee2af6560ec060bd741e98754dc0`.
The advisory is [GHSA-pwh2-fpfr-x5gf](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-pwh2-fpfr-x5gf).

The script waits until the seeded background replay reaches 43%, checks the
public site and category administration route, signs in with the isolated lab
administrator, opens the category form, and submits a valid GIF containing a
fixed text-only execution check. It then requests the uploaded file and records
the successful response. The vulnerable file was captured only inside the lab;
the committed webroot contains its inert defanged stub. No operating-system
command was run.

The six attacker requests are labeled from their `X-Lab-Step` identifiers in
the replay sidecar and the corresponding request lines in
`evidence/access.log.gz`:

| Step | Access-log line | Result |
|---|---:|---|
| `site_check` | 6,451 | HTTP 200; reconnaissance |
| `category_admin_probe` | 6,452 | HTTP 200; reconnaissance |
| `editor_login` | 6,453 | HTTP 200; valid account access |
| `category_editor_open` | 6,454 | HTTP 200; valid account access |
| `category_image_upload` | 6,455 | HTTP 200; root cause |
| `uploaded_file_execution` | 6,456 | HTTP 200; execution confirmed |

The attack steps fall at 42.989%â€“43.023% of the 15,006-row access log. The
15,000 background rows comprise 12,077 visitors and 2,923 scanner rows. There
are 10,384 client identities and 903 User-Agents; the largest client share is
0.973% and the largest User-Agent share is 4.407%. Visitor 2xx/3xx success is
99.959%; scanner requests are retained.

The collector defanged two changed files: the category image and a phpMyFAQ
runtime tracking file larger than the public snapshot limit. Their original
hashes and sizes remain in `evidence/manifest.tsv` and
`evidence/defanged.tsv`; full contents remain in the encrypted local capture.
The vulnerable upload's POSIX filename ends in two dots, which Windows cannot
check out as a normal working-tree path. Its inert snapshot stub is stored as
`images/category-1-.php.__posix_trailing_dots_2`; `replay/restore.json` maps
that portable snapshot name to the original manifest path, and
`restore_webroot.py` restores the original name with an extended Windows path.
The scenario folder is 3,469,775 bytes. Schema validation, byte-identical
ground-truth regeneration, evidence parsing, and replay self-check pass. The
restore overlay contains the five static access-denial index files generated
by phpMyFAQ setup. The restored tree includes all 2,881 manifest entries.
Defender realtime protection was enabled and the scan found zero detections.
