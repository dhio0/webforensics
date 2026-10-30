# Benchmark v2 sources

This file records verification performed while selecting v2 dependencies. A source
listed as a candidate is not evidence that a scenario has been replayed.

## Verified release candidates

| Name | Exact version / digest | License | URL / advisory |
|---|---|---|---|
| WordPress | 5.5.3, Docker Hub `linux/amd64` manifest `sha256:07fffd786a81e5f23fe4f5f58a181b43084ed232e1db732415023848937b9c73` | GPL-2.0-or-later | [official image](https://hub.docker.com/_/wordpress), [5.5.3 archive](https://wordpress.org/wordpress-5.5.3.tar.gz) |
| WordPress File Manager | 6.0, archive SHA-256 `f70dd0e72d030795639e3c59e4a0c73005cabf07e1c91efaa34d0808a5995c9d` | GPLv2 (plugin header) | [version archive](https://downloads.wordpress.org/plugin/wp-file-manager.6.0.zip), [CVE-2020-25213](https://nvd.nist.gov/vuln/detail/CVE-2020-25213) |
| s01 WordPress app image | Docker image content digest `sha256:5f928299d26e3b67c82df6f3d4733def009812e76ce908e5fd81f4e3db6fdddf` | WordPress and plugin licenses above | `replay/restore.json` |
| phpMyFAQ | 3.2.5; affected by CVE-2024-27299 | MPL-2.0 (`LICENSE` at the 3.2.5 tag) | [license](https://github.com/thorsten/phpMyFAQ/blob/3.2.5/LICENSE), [GitHub advisory](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-qgxx-4xv5-6hcw), [fix commit](https://github.com/thorsten/phpMyFAQ/commit/1b68a5f89fb65996c56285fa636b818de8608011) |
| Contact Form 7 | 5.3.1, WordPress.org version archive | GPL-2.0-or-later | [version archive](https://downloads.wordpress.org/plugin/contact-form-7.5.3.1.zip), [CVE-2020-35489 advisory](https://nvd.nist.gov/vuln/detail/CVE-2020-35489) |
| MariaDB | 10.5.27, Docker Hub `linux/amd64` manifest `sha256:6a12617127de7ad42895232407abf403ae79f465bb818a8ac7ffbb97b8b18937` | GPL-2.0 | [official image](https://hub.docker.com/_/mariadb) |
| nginx | 1.27.5-alpine, image digest `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` | BSD-2-Clause | [official image](https://hub.docker.com/_/nginx) |
| Public sector web-server logs | Zenodo record 20001206, v1 (2026-05-03) | MIT (`mit-license` in Zenodo API metadata) | [record](https://zenodo.org/records/20001206) |
| NASA KSC HTTP access logs | July and August 1995 traces | Freely redistributable (source page explicitly grants redistribution) | [dataset description and download links](https://ita.ee.lbl.gov/html/contrib/NASA-HTTP.html) |
| sqlmap | commit `c42ebd7acf47c88b6407995dd9842a2eb5d6534d` | GPL-2.0 | [pinned source](https://github.com/sqlmapproject/sqlmap/tree/c42ebd7acf47c88b6407995dd9842a2eb5d6534d) |
| Weevely3 | 4.0.3, commit `3d62e889871a62a344365b6a2d02b35c5ac1e946` | GPL-3.0 | [pinned source](https://github.com/epinna/weevely3/tree/3d62e889871a62a344365b6a2d02b35c5ac1e946) |
| commix | commit `625c0c46e4257c457774e39bd896307397eaab03` | GPL-3.0-or-later | [pinned source](https://github.com/commixproject/commix/tree/625c0c46e4257c457774e39bd896307397eaab03) |
| THC Hydra | commit `a247d063e35f24218f55cc3c705e20073d1379eb` | AGPL-3.0 | [pinned source](https://github.com/vanhauser-thc/thc-hydra/tree/a247d063e35f24218f55cc3c705e20073d1379eb) |
| Python cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | [PyPI release](https://pypi.org/project/cryptography/50.0.2/) |
| Python attacker base | 3.13.18 slim-bookworm, `linux/amd64` digest `sha256:70bda1e795ded2a684ef9815955e05829b14ee5bb5c3eb2a940648e88f10fce9` | PSF-2.0 | [official image](https://hub.docker.com/_/python) |
| Weevely attacker image | local image ID `sha256:09ea4569baac3e4bc06b041fa4523ee1f0482ae99fc4ce91e36e34b3edb49e10` | GPL-3.0 | [pinned Weevely3 source](https://github.com/epinna/weevely3/tree/3d62e889871a62a344365b6a2d02b35c5ac1e946) |
| WordPress app image | local image ID `sha256:a29b594443b1956b91a97cbcb2f360d2be940e70cfc0dd8dd1c2633be23e2910` | GPL-2.0-or-later | built from the pinned WordPress image and File Manager archive above |
| Collector image | local image ID `sha256:432cbd4daf7b64945aa11be4d91c12df270800e2a4684514adbfe458a504fd8e` | MIT (project code) | built from the pinned Python base and `cryptography` 50.0.2 |
| requests | 2.32.4 | Apache-2.0 | [PyPI release](https://pypi.org/project/requests/2.32.4/) |

The external image digests above are pinned for this Docker Desktop `linux/amd64` host.
The locally built image IDs identify the artifacts used for s01. The Zenodo API metadata reports MIT and the record describes
Organization X/Y web-server access and error logs. NASA's source format does not
include a user-agent, so a replay must mark its user-agent as unavailable rather than
invent one.

## Candidates requiring further verification before use

| Name | Version / CVE candidate | Status |
|---|---|---|
| PHPGurukul Student Record System | 3.20; CVE-2024-44640 (`add-course.php`, SQL injection) | NVD confirms the affected version and endpoint. No redistribution license was found during this check. Do not commit its source snapshot until the license is verified. |
| PHPGurukul Small CRM | 3.0; CVE-2024-44644 (`manage-tickets.php`, SQL injection) | The published advisory names the endpoint, but no explicit OSI-approved license or source release with that license was verified. Not eligible for redistribution. |
| phpMyFAQ | 3.2.5; CVE-2024-27299 (`phpmyfaq/src/phpMyFAQ/News.php`) | Explicit MPL-2.0 license and maintainer fix provenance verified, but this is a full FAQ platform; the upstream repository is about 52.8 MB and does not fit the requested small-app scenario. Not selected for s03. |
| curl | exact package version not yet pinned | Tool and license verification still required. |
| Docker attacker/app images | final image digests | Build and pin only after tool versions and application set are fixed. |

## CVE verification notes

- [CVE-2024-27299](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-qgxx-4xv5-6hcw):
  phpMyFAQ 3.2.5 is affected and 3.2.6 is patched. The maintainer's fix commit names
  `phpmyfaq/src/phpMyFAQ/News.php` and changes the vulnerable `authorEmail` value at
  lines 289 and 335. The 3.2.5 source tag has an explicit MPL-2.0 license. This verifies
  the source and line provenance for a possible s03 record; no s03 attack has been run.

- [CVE-2020-35489](https://nvd.nist.gov/vuln/detail/CVE-2020-35489): Contact Form 7
  releases before 5.3.2 are affected. CERT-In's [advisory](https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIVN-2020-0442&pageid=PUBVLNOTES01)
  confirms unauthenticated file-type filter bypass for 5.3.1 and earlier and recommends
  5.3.2. This supports pinning 5.3.1 as the vulnerable release. The NVD record says
  filenames containing special characters permit unrestricted upload/RCE.
- [CVE-2024-44640](https://nvd.nist.gov/vuln/detail/CVE-2024-44640): NVD identifies
  PHPGurukul Student Record System 3.20 and `add-course.php` parameters `course-short`,
  `course-full`, and `cdate`. It remains a candidate only because the source license
  needs clarification.
- [CVE-2024-44644](https://github.com/advisories/ghsa-x7rr-7j6w-6hc8): the advisory
  identifies PHPGurukul Small CRM 3.0 and SQL injection through `frm_id` and `aremark`
  in `manage-tickets.php`; it provides no verified OSI license or fix commit.
- The phpMyFAQ 3.2.5 tag's explicit MPL-2.0 license and the maintainer advisory/fix
  commit verify a PHP SQL injection source, but phpMyFAQ is a full FAQ platform rather
  than a small PHP application. Its upstream repository size is about 52.8 MB ([repository metadata](https://awesome.ecosyste.ms/projects/github.com%2Fthorsten%2FphpMyFAQ)).

## s01 verification

s01 used CVE-2020-25213 in WordPress File Manager 6.0. NVD describes the unauthenticated
upload and execution path caused by an unsafe elFinder connector being exposed as PHP.
In the isolated stack, the upload endpoint accepted the request, the uploaded file was
served by the Apache/PHP WordPress image, and the pinned Weevely 4.0.3 agent completed
three commands. This is the in-lab execution check for the CVE selected for s01. The
pilot did not use Contact Form 7 or claim an in-lab result for CVE-2020-35489.

Weevely and requests were installed in the attacker image. The other listed attack
tools remain uninstalled and unverified for this pilot. No additional scenarios are
claimed by this inventory.
