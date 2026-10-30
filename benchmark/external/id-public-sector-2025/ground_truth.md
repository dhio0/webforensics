# Ground truth: Indonesian public-sector web logs (Zenodo 20001206), pre-registered

Written from the dataset's own description and its labelling rules, plus log metadata
(line counts, timestamps, client IPs, request endpoints) read without interpreting payload
content. Not edited after the tool ran; its SHA-256 is recorded in the results. Tool for
run 1: main at 2ad5d68 (D84-D87), unchanged until run 1 is scored. This is a held-out
case: no rule may change before run 1 is scored.

## Source
"Web Server Log Dataset", Zenodo DOI 10.5281/zenodo.20001206 (2026-05-03), MIT license,
anonymous authors. Real logs of two Indonesian public-sector organizations (X, Y),
anonymized; client IPs appear remapped by the authors. Archive MD5s:
organization-x.zip b4bf79effa6f3ee1b9e53f278d916620,
organization-y.zip b1925ff7f043c391d501cfd404e0df10.
Authors' ground truth = YAML line-pattern labelling rules (all patterns of a rule must
match a line; unmatched lines are benign), plus one sentence of context per organization.

## Evidence and its limits (stated before the run)
- **Access logs only, no webroot and no file listing.** The tool's file-first method
  cannot seed from files; it is given an empty webroot. So this case does NOT test file
  correlation, timestomp, code localization or file-based webshell detection. It tests, at
  real scale: log attack-rules, actor attribution, FALSE ACCUSATIONS, evidence gaps,
  runtime, peak memory, and report readability.
- auth.log and syslog are not tool inputs (it reads access + error logs). SSH brute force
  and sudo activity are therefore out of web-side scope.

## Organization X  (Apache)
- Scale: 16 access-log files, 213,205 lines, 2025-08-12 to 2025-10-07, plus error logs.
- Dataset says: "extensive reconnaissance and exploitation attempts", "no privilege
  escalation identified". Labels: dir_scan, path_traversal, rce_shell/rce_read_file/
  rce_sysinfo/rce_java, api_call (F5 mgmt/tm/util/bash), cross_site_scripting,
  file_inclusion, sql_injection, etc. These are ATTEMPTS, not a confirmed compromise.
- Expected outcome:
  - **No compromise reported** (none succeeded, and there is no webroot to confirm one).
    Reporting a compromise here would be a false positive.
  - Attack attempts appear as grouped unrelated/background activity, not as accusations.
  - **False accusations (affected files, named attacker actors) = 0.** An "unlinked SQLi
    login bypass" note (D71) is allowed only if a login endpoint truly returned a
    success-shaped response; it is reported, not an accusation.
  - Runs in well under a minute.

## Organization Y  (OpenLiteSpeed + CyberPanel)
- Scale: 163 access-log files, 7,426,129 lines, ~22 virtual hosts under log/home/*/logs,
  plus log/usr/local/lsws/logs/access.log and the panel logs under log/usr/local/lscp/.
  Timestamps +0000. Also large error/auth/syslog files (syslog alone ~29M lines).
- Dataset says: "a successful privilege escalation incident on 2025-04-29, 05:28-07:07
  local time." The server clock is +0000 and the web-observable activity sits in that
  window, so treat the window as 2025-04-29 05:28-07:07 UTC.
- The incident, web-observable part (CyberPanel admin interface,
  log/usr/local/lscp/cyberpanel/logs/access.log):
  - Actor 243.23.54.175, active 2025-04-29 05:46:57-07:32:17 UTC.
  - Authenticated to CyberPanel (POST /verifyLogin x7), then POST
    /websites/submitWebsiteCreation x3 and /dns/zoneCreation, creating gambling-brand
    virtual hosts (labels: pragmaslot, mawartoto = Indonesian judi-online SEO spam),
    POST /websites/submitWebsiteDeletion x2, /filemanager/controller x2, and 316
    /websites/installWordpressStatus polls.
  - The SSH/sudo side (labels bruteforce_login_success / ssh_login_success for
    27.116.61.59, sudo via /tmp/lscpd) is in auth.log, NOT a tool input.
- Expected outcome (held-out, honest prediction):
  - The incident is authenticated management-plane API calls. They match NO web-attack
    rule (no SQLi/upload/webshell/traversal/RCE-in-URL/XSS/defacement payload), and there
    is no webroot. So the tool is EXPECTED TO MISS this compromise from access logs alone.
    A correct report then says "no compromise found", which does not claim the server is
    clean. Flagging 243.23.54.175 would be a (welcome) bonus, not expected.
  - **False accusations = 0** is the primary metric at 7.4M-line scale.
  - Scale: runtime and peak memory on 15.7 GB RAM. Baseline ~1 GB per 1M lines, so ~7-8 GB
    is plausible; an out-of-memory or very slow run is a valid, reportable result.

## Metrics (both organizations)
1. Compromise reported? (X: should be no; Y: likely no, and that is a documented miss).
2. IPs named as attacker actors, split into: (a) a labelled incident IP (243.23.54.175 for
   Y), (b) IPs with at least one line matching a labelling rule (attackers per the
   dataset), (c) IPs with no labelled line = true false accusations. Only (c) is a failure.
3. Affected files (must be 0: no webroot).
4. Background/attack-noise groups surfaced (sanity that rules fire at all).
5. Gaps reported.
6. Runtime, peak memory, report size.

## Run protocol
Run 1: tool at 2ad5d68 unchanged. Per organization, all access logs together
(`--log-format apache_combined`), error logs where they parse as Apache, empty
`--webroot`. Score with score.py next to this file. Fixes, if any, come after run 1 is
scored and are reported as post-hoc run 2; the lab benchmark and cases 1-3 must score the
same afterwards.
