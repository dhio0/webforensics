# Benchmark v2 sources

This file records verification performed while selecting v2 dependencies. A source
listed as a candidate is not evidence that a scenario has been replayed.

## Verified release candidates

| Name | Exact version / digest | License | URL / advisory |
|---|---|---|---|
| WordPress | 5.5.3, Docker Hub `linux/amd64` manifest `sha256:07fffd786a81e5f23fe4f5f58a181b43084ed232e1db732415023848937b9c73` | GPL-2.0-or-later | [official image](https://hub.docker.com/_/wordpress), [5.5.3 archive](https://wordpress.org/wordpress-5.5.3.tar.gz) |
| Contact Form 7 | 5.3.1, WordPress.org version archive | GPL-2.0-or-later | [version archive](https://downloads.wordpress.org/plugin/contact-form-7.5.3.1.zip), [CVE-2020-35489 advisory](https://nvd.nist.gov/vuln/detail/CVE-2020-35489) |
| MariaDB | 10.5.27, Docker Hub `linux/amd64` manifest `sha256:6a12617127de7ad42895232407abf403ae79f465bb818a8ac7ffbb97b8b18937` | GPL-2.0 | [official image](https://hub.docker.com/_/mariadb) |
| nginx | 1.27.5-alpine, Docker Hub `linux/amd64` manifest `sha256:2079782fcbba5c682e6de06e50c168aa39919c6c6ddd59ea183e9460b6d5679f` | BSD-2-Clause | [official image](https://hub.docker.com/_/nginx) |
| Public sector web-server logs | Zenodo record 20001206, v1 (2026-05-03) | MIT (`mit-license` in Zenodo API metadata) | [record](https://zenodo.org/records/20001206) |
| NASA KSC HTTP access logs | July and August 1995 traces | Freely redistributable (source page explicitly grants redistribution) | [dataset description and download links](https://ita.ee.lbl.gov/html/contrib/NASA-HTTP.html) |
| sqlmap | commit `c42ebd7acf47c88b6407995dd9842a2eb5d6534d` | GPL-2.0 | [pinned source](https://github.com/sqlmapproject/sqlmap/tree/c42ebd7acf47c88b6407995dd9842a2eb5d6534d) |
| Weevely3 | 4.0.3, commit `3d62e889871a62a344365b6a2d02b35c5ac1e946` | GPL-3.0 | [pinned source](https://github.com/epinna/weevely3/tree/3d62e889871a62a344365b6a2d02b35c5ac1e946) |
| commix | commit `625c0c46e4257c457774e39bd896307397eaab03` | GPL-3.0-or-later | [pinned source](https://github.com/commixproject/commix/tree/625c0c46e4257c457774e39bd896307397eaab03) |
| THC Hydra | commit `a247d063e35f24218f55cc3c705e20073d1379eb` | AGPL-3.0 | [pinned source](https://github.com/vanhauser-thc/thc-hydra/tree/a247d063e35f24218f55cc3c705e20073d1379eb) |
| Python cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | [PyPI release](https://pypi.org/project/cryptography/50.0.2/) |

The WordPress, MariaDB, and nginx image tags were available from Docker Hub when
checked; the digests above are platform-specific manifests for this Docker Desktop
`linux/amd64` host. The Zenodo API metadata reports MIT and the record describes
Organization X/Y web-server access and error logs. NASA's source format does not
include a user-agent, so a replay must mark its user-agent as unavailable rather than
invent one.

## Candidates requiring further verification before use

| Name | Version / CVE candidate | Status |
|---|---|---|
| PHPGurukul Student Record System | 3.20; CVE-2024-44640 (`add-course.php`, SQL injection) | NVD confirms the affected version and endpoint. No redistribution license was found during this check. Do not commit its source snapshot until the license is verified. |
| curl | exact package version not yet pinned | Tool and license verification still required. |
| Docker attacker/app images | final image digests | Build and pin only after tool versions and application set are fixed. |

## CVE verification notes

- [CVE-2020-35489](https://nvd.nist.gov/vuln/detail/CVE-2020-35489): Contact Form 7
  releases before 5.3.2 are affected. CERT-In's [advisory](https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIVN-2020-0442&pageid=PUBVLNOTES01)
  confirms unauthenticated file-type filter bypass for 5.3.1 and earlier and recommends
  5.3.2. This supports pinning 5.3.1 as the vulnerable release. The NVD record says
  filenames containing special characters permit unrestricted upload/RCE.
- [CVE-2024-44640](https://nvd.nist.gov/vuln/detail/CVE-2024-44640): NVD identifies
  PHPGurukul Student Record System 3.20 and `add-course.php` parameters `course-short`,
  `course-full`, and `cdate`. It remains a candidate only because the source license
  needs clarification.

The four upstream tool commits and their license files were inspected, but none has yet
been installed or run in the v2 attacker container. No v2 replay or app installation is
claimed by this source inventory.
