# Benchmark v2 sources

This file records verification performed while selecting v2 dependencies. A source
listed as a candidate is not evidence that a scenario has been replayed.

## Verified release candidates

| Name | Exact version / digest | License | URL / advisory |
|---|---|---|---|
| WordPress | 5.5.3, Docker Hub `linux/amd64` manifest `sha256:07fffd786a81e5f23fe4f5f58a181b43084ed232e1db732415023848937b9c73` | GPL-2.0-or-later | [official image](https://hub.docker.com/_/wordpress), [5.5.3 archive](https://wordpress.org/wordpress-5.5.3.tar.gz) |
| WordPress File Manager | 6.0, archive SHA-256 `f70dd0e72d030795639e3c59e4a0c73005cabf07e1c91efaa34d0808a5995c9d` | GPLv2 (plugin header) | [version archive](https://downloads.wordpress.org/plugin/wp-file-manager.6.0.zip), [CVE-2020-25213](https://nvd.nist.gov/vuln/detail/CVE-2020-25213) |
| s01 WordPress app image | Docker image content digest `sha256:9f583315107a756a0398b1d7b556afdc054230c5320f6b07291a3d2744e120d8` | WordPress and plugin licenses above | `replay/restore.json` |
| s07 WordPress app image | image ID `sha256:9237cb65bfe4c07be6e755894506c717ef86fa91a06a526be0ca5843080cede6` | GPL-2.0-or-later | WordPress 5.5.3 and File Manager 6.0 sources above; `s07/replay/restore.json` |
| s08 WordPress app image | image ID `sha256:64d5a59f484d846454c48390965abec5ba5f6715301c3e9a05fc83904eb7f6e3` | GPL-2.0-or-later | WordPress 5.5.3 and File Manager 6.0 sources above; `s08/replay/restore.json` |
| s10 WordPress app image | image ID `sha256:7f9b718aebbc5511d8299390ed09ae50beca847811292743908045d9c47aa294` | GPL-2.0-or-later | WordPress 5.5.3 and File Manager 6.0 sources above; `s10/replay/restore.json` |
| s12 WordPress app image | image ID `sha256:d7e6a00b2d27010352196b00593dba9921a45adf5bd828ec5fa246e5c141cbc4` | GPL-2.0-or-later | WordPress 5.5.3 and File Manager 6.0 sources above; `s12/replay/restore.json` |
| s11 WordPress app image | image ID `sha256:069b75bdcf4e1b7664d87a7bd6aa8a1ea5232fcf84fb390405f7a46daf486851` | GPL-2.0-or-later | WordPress 5.5.3 and File Manager 6.0 sources above; `s11/replay/restore.json` |
| s11 attacker image | image ID `sha256:7dfee85a72b0b574dec24a951af3137af862b6f292bba20cecce486fa3274eaa` | GPL-2.0 for sqlmap; other tool licenses above | contains the pinned sqlmap source listed above and the tools listed for s10; used for the no-compromise scanner replay |
| phpMyFAQ | 3.2.5 source tag `ee05654763ef0f16137d3bd21ec50e2f21ffb8f8`; codeload archive SHA-256 `282b638d7ecda25d6a803d16d9865c6b8aa0516ec9ed6d24bfadabdc6800d05f`; s03 image `sha256:ad332294411c32cded91f9bdb2f650652ada270b20e07db6927dfa368d65f390` | MPL-2.0 (`LICENSE` at the 3.2.5 tag) | [license](https://github.com/thorsten/phpMyFAQ/blob/3.2.5/LICENSE), [GitHub advisory](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-qgxx-4xv5-6hcw), [fix commit](https://github.com/thorsten/phpMyFAQ/commit/1b68a5f89fb65996c56285fa636b818de8608011) |
| s04 phpMyFAQ app image | 3.2.5, image ID `sha256:1bb7e47b771e7061c2265143b13592dcd02dcae91dea9642e1929f815be790bd` | MPL-2.0 | [source tag and license](https://github.com/thorsten/phpMyFAQ/tree/3.2.5), [CVE-2024-28105 advisory](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-pwh2-fpfr-x5gf) |
| DVWA | source commit `a1978a2fed195acd093010af6395f86a281537ca`, source archive SHA-256 `4bd1cb5dda6bdb889055bf0bcdbaf8fd9562ac358bb61918f3c0cb5199a76258` | GPL-3.0-or-later (stated in upstream README) | [pinned upstream source](https://github.com/digininja/DVWA/tree/a1978a2fed195acd093010af6395f86a281537ca), [README/license](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/README.md) |
| s05 DVWA app image | image ID `sha256:920e46e2097ab0521d31f782475e6aacbc7beca5e71485a507fe378e6fdfc849` | GPL-3.0-or-later | built from the pinned DVWA source above and the pinned PHP Apache base image |
| s06 DVWA app image | image ID `sha256:0131a6760d12ee1f7cc3841aa724f4a87b6049d47b89fe5db095ada1c857ec76` | GPL-3.0-or-later | built from the pinned DVWA source above; `s06/replay/restore.json` |
| s02 DVWA app image | image ID `sha256:f88bd59c68eaae46c3677866e3d1f80f3612eb3c41983e9cabc56ff7d0c7e99b` | GPL-3.0-or-later | built from the pinned DVWA source above; `s02/replay/restore.json` |
| s02 attacker image | image ID `sha256:4efec7d3150f08434fc7ac22aa661e2a06506c1abba284474d1b1845b3df0b58` | GPL-2.0 for sqlmap; GPL-3.0 for Weevely3; other tool licenses above | contains pinned sqlmap and Weevely3; `s02/replay/restore.json` |
| Contact Form 7 | 5.3.1, WordPress.org version archive | GPL-2.0-or-later | [version archive](https://downloads.wordpress.org/plugin/contact-form-7.5.3.1.zip), [CVE-2020-35489 advisory](https://nvd.nist.gov/vuln/detail/CVE-2020-35489) |
| MariaDB | 10.5.27, Docker Hub `linux/amd64` manifest `sha256:6a12617127de7ad42895232407abf403ae79f465bb818a8ac7ffbb97b8b18937` | GPL-2.0 | [official image](https://hub.docker.com/_/mariadb) |
| PostgreSQL | 16.6-alpine, manifest digest `sha256:1d04b9ba1d4996401f2552b51beda8187f175c0645c091e4781134fc9c9a3eef` | PostgreSQL License | [official image](https://hub.docker.com/_/postgres) |
| PHP Apache | `php:8.1-apache-bookworm`, manifest digest `sha256:a935f4a5717427519337269d5d1c89968cc27ab84d1c8d5d7b5363672d800cd5` | PHP License | [official image](https://hub.docker.com/_/php) |
| Composer | `composer:2.8.12`, manifest digest `sha256:5248900ab8b5f7f880c2d62180e40960cd87f60149ec9a1abfd62ac72a02577c` | MIT | [official image](https://hub.docker.com/_/composer) |
| nginx | 1.27.5-alpine, image digest `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` | BSD-2-Clause | [official image](https://hub.docker.com/_/nginx) |
| Public sector web-server logs | Zenodo record 20001206, v1 (2026-05-03) | MIT (`mit-license` in Zenodo API metadata) | [record](https://zenodo.org/records/20001206) |
| NASA KSC HTTP access logs | July and August 1995 traces | Freely redistributable (source page explicitly grants redistribution) | [dataset description and download links](https://ita.ee.lbl.gov/html/contrib/NASA-HTTP.html) |
| Web Server Log Dataset, Organization X | Zenodo record 20001206, v1; `organization-x.zip` MD5 `b4bf79effa6f3ee1b9e53f278d916620` | MIT (`mit-license` in the Zenodo API metadata) | [record and files](https://zenodo.org/records/20001206) |
| sqlmap | commit `c42ebd7acf47c88b6407995dd9842a2eb5d6534d` | GPL-2.0 | [pinned source](https://github.com/sqlmapproject/sqlmap/tree/c42ebd7acf47c88b6407995dd9842a2eb5d6534d) |
| Weevely3 | 4.0.3, commit `3d62e889871a62a344365b6a2d02b35c5ac1e946` | GPL-3.0 | [pinned source](https://github.com/epinna/weevely3/tree/3d62e889871a62a344365b6a2d02b35c5ac1e946) |
| commix | commit `625c0c46e4257c457774e39bd896307397eaab03` | GPL-3.0-or-later | [pinned source](https://github.com/commixproject/commix/tree/625c0c46e4257c457774e39bd896307397eaab03) |
| THC Hydra | commit `a247d063e35f24218f55cc3c705e20073d1379eb` | AGPL-3.0 | [pinned source](https://github.com/vanhauser-thc/thc-hydra/tree/a247d063e35f24218f55cc3c705e20073d1379eb) |
| Python cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | [PyPI release](https://pypi.org/project/cryptography/50.0.2/) |
| Python attacker base | 3.13.18 slim-bookworm, `linux/amd64` digest `sha256:70bda1e795ded2a684ef9815955e05829b14ee5bb5c3eb2a940648e88f10fce9` | PSF-2.0 | [official image](https://hub.docker.com/_/python) |
| Weevely/sqlmap attacker image | s03 local image ID `sha256:6b46cd5ed803cbc6e3d5692a8aa9f3fbf0f5e2de55b87dd3d608b141215dc376` | GPL-3.0 / GPL-2.0 | [pinned Weevely3](https://github.com/epinna/weevely3/tree/3d62e889871a62a344365b6a2d02b35c5ac1e946), [pinned sqlmap](https://github.com/sqlmapproject/sqlmap/tree/c42ebd7acf47c88b6407995dd9842a2eb5d6534d) |
| s05 attacker image | local image ID `sha256:94c59b455d107dc4a7cd9cc68b3aec414f93ae7cd563ecb3c5b431d5963485f0` | GPL-3.0-or-later for Commix and Weevely; GPL-2.0 for sqlmap | contains the pinned [Commix](https://github.com/commixproject/commix/tree/625c0c46e4257c457774e39bd896307397eaab03), [Weevely3](https://github.com/epinna/weevely3/tree/3d62e889871a62a344365b6a2d02b35c5ac1e946), and [sqlmap](https://github.com/sqlmapproject/sqlmap/tree/c42ebd7acf47c88b6407995dd9842a2eb5d6534d) sources |
| s07 attacker image | local image ID `sha256:4c06eb7d61efc37ec4484f7ee57782876ac142ef13d1d50ae057aa3fab1f6764` | AGPL-3.0 for Hydra; other tool licenses above | contains the pinned [THC Hydra](https://github.com/vanhauser-thc/thc-hydra/tree/a247d063e35f24218f55cc3c705e20073d1379eb) build and the tools listed for s05 |
| s08 attacker image | local image ID `sha256:b1b419b1695bcfc8ca6392f3c079983490a655a2ece93b0e19d8f801983f3082` | GPL-3.0 for Weevely3; other tool licenses above | contains the pinned [Weevely3](https://github.com/epinna/weevely3/tree/3d62e889871a62a344365b6a2d02b35c5ac1e946) build and the tools listed for s07 |
| s10 attacker image | local image ID `sha256:4f492b38858335ffc9dd5e7ac18d296b3bd59f0d13de3ce7557ab75a6610da51` | GPL-3.0 for Weevely3; other tool licenses above | contains the pinned [Weevely3](https://github.com/epinna/weevely3/tree/3d62e889871a62a344365b6a2d02b35c5ac1e946) build and the tools listed for s08 |
| s12 attacker image | local image ID `sha256:acaeb94a6cd785b5666061a907c78f06699ce33ff35aaec1c9a94dbf18bf9ef7` | GPL-3.0 for Weevely3; other tool licenses above | contains the tools listed for s10; used only to run the benign isolated replay |
| s12 local cache fixture | versions 1.0 and 1.1; source SHA-256 `4228181643692e280049f339ea1153ddd668880e260f73df13d93245b37cd068` and `c6ba6f948994088302d96b79f52b4106f8601a5a6fe17c107cc109e36fa78b78` | MIT (project fixture) | `lab/v2/scenarios/fixtures/s12-cache-v1.php` and `s12-cache-v1.1.php`; version 1.1 was uploaded as a local update package in the isolated replay |
| WordPress app image | local image ID `sha256:9f583315107a756a0398b1d7b556afdc054230c5320f6b07291a3d2744e120d8` | GPL-2.0-or-later | built from the pinned WordPress image and File Manager archive above |
| Collector image | s03 local image ID `sha256:063261e260ea4a1691855a693c5f88fc719e12c278933872167adabdc383731b` | MIT (project code) | built from the pinned Python base and `cryptography` 50.0.2 |
| requests | 2.32.4 | Apache-2.0 | [PyPI release](https://pypi.org/project/requests/2.32.4/) |

The external image digests above are pinned for this Docker Desktop `linux/amd64` host.
The locally built image IDs identify the artifacts used for each scenario as recorded in
its `replay/restore.json`. The Zenodo API metadata
reports MIT and describes Organization X/Y web-server logs. Organization X supplies
real methods, request targets, statuses, and User-Agent values for v2 background rows.
Its public access log anonymizes nearly all client addresses to the same value, so the
replay corpus pairs those request rows in chronological order with evenly sampled NASA
client identities. NASA User-Agent values are never substituted into visitor requests.
The exact transformation and resulting diversity counts are recorded per scenario.

## Candidates requiring further verification before use

| Name | Version / CVE candidate | Status |
|---|---|---|
| PHPGurukul Student Record System | 3.20; CVE-2024-44640 (`add-course.php`, SQL injection) | NVD confirms the affected version and endpoint. No redistribution license was found during this check. Do not commit its source snapshot until the license is verified. |
| PHPGurukul Small CRM | 3.0; CVE-2024-44644 (`manage-tickets.php`, SQL injection) | The published advisory names the endpoint, but no explicit OSI-approved license or source release with that license was verified. Not eligible for redistribution. |
| curl | exact package version not yet pinned | Tool and license verification still required. |
| Docker attacker/app images | final image digests | Build and pin only after tool versions and application set are fixed. |

## CVE verification notes

- [CVE-2024-27299](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-qgxx-4xv5-6hcw):
  phpMyFAQ 3.2.5 is affected and 3.2.6 is patched. The maintainer's fix commit names
  `phpmyfaq/src/phpMyFAQ/News.php` and changes the vulnerable `authorEmail` value at
  lines 289 and 335. The 3.2.5 source tag has an explicit MPL-2.0 license. This verifies
  the source and line provenance recorded in s03. The isolated s03 replay confirmed the
  authenticated Save News SQL injection with a short database-delay check; it created no
  attacker file and ran no operating-system command.

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

Weevely and requests were installed in the initial attacker image. The image also pins
sqlmap commit `c42ebd7acf47c88b6407995dd9842a2eb5d6534d`; its generic s03 check ran and
did not identify the documented cross-field condition. A separate short-delay request
confirmed the vulnerability in the isolated lab. Other listed attack tools remain
unverified.
