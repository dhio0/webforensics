# Rule catalog

Every rule the tool can fire, what it matches, what it does **not** prove, and the false positives seen so far. A rule match is a lead, never a verdict on its own: the engine decides a compromise only when a file or a log-only script ties the leads together (plan §4). `tests/unit/test_rules_doc.py` fails if a rule exists in the code without a section here.

Severity and confidence are those of the finding. "Seen FP" lists false positives found on real evidence, and the decision that dealt with them.

## Access-log rules (`src/webforensics/detect/log_rules.py`)

Matched on the percent-decoded request (decoded twice), the query, the path or the user agent.

### LOG-SQLI-UNION
- **Matches:** `UNION [ALL] SELECT`, with spaces, `+` or comments between the words.
- **Severity / confidence:** high / high. MITRE T1190.
- **Does not prove:** that the query ran, or that it returned data. A 200 means the page answered.
- **Seen FP:** none from plain words ("union station" does not match).

### LOG-SQLI-TAUTOLOGY
- **Matches:** `OR 1=1`, `' or 'a'='a`, after a quote or a space.
- **Severity / confidence:** high / medium. T1190.
- **Does not prove:** a bypass. Login success is judged separately (D48, D71).
- **Seen FP:** none known; `1 and x=y` is not a tautology and does not match.

### LOG-SQLI-BLIND
- **Matches:** `sleep(`, `pg_sleep(`, `benchmark(`, `extractvalue(`, `updatexml(`, `waitfor delay`.
- **Severity / confidence:** high / high. T1190.
- **Does not prove:** a delay happened; access logs rarely show request time.
- **Seen FP:** none.

### LOG-SQLI-SCHEMA
- **Matches:** `information_schema`, `into outfile|dumpfile`, `load_file(`.
- **Severity / confidence:** high / high. T1190.
- **Does not prove:** a file was written. `INTO OUTFILE` followed by a request for that name is how a write is shown (D85).
- **Seen FP:** none.

### LOG-SQLI-QUOTE-COMMENT
- **Matches:** a quote, then `--`, `#` or `/*`.
- **Severity / confidence:** medium / medium. T1190.
- **Does not prove:** injection; it is the weakest SQLi signal.
- **Seen FP:** none in the cases so far; possible on free-text search fields.

### LOG-TRAVERSAL-DOTS
- **Matches:** two or more `../` (or `..\`).
- **Severity / confidence:** high / medium. T1190.
- **Does not prove:** a file was read.
- **Seen FP:** a single `../` in normalized paths does not match.

### LOG-TRAVERSAL-SENSITIVE
- **Matches:** `/etc/passwd`, `/etc/shadow`, `win.ini`, `boot.ini`, `/proc/self/environ`.
- **Severity / confidence:** high / high. T1190, T1083.
- **Does not prove:** the file was disclosed. A same-sized answer to many probes is a catch-all page.
- **Seen FP:** `passwd-policy.html` does not match.

### LOG-XSS-PROBE
- **Matches (query only):** `<script`, a quote then `><tag`, `javascript:`, `onerror=` and similar.
- **Severity / confidence:** low / medium. T1190.
- **Does not prove:** stored or reflected XSS.
- **Seen FP:** comparisons in a search (`a > b and c < d`) do not match. Added in D87.

### LOG-RCE-CODE-INJECTION
- **Matches:** PHP code or a code-running callback in the request: `eval(`, `assert(`, `base64_decode(`, `system('`, `<?php`, `php -r`, Drupal render-array keys (`[#post_render]`).
- **Severity / confidence:** high / medium. T1190, T1059.
- **Does not prove:** the code ran. A 2xx answer and a later script are what link it (D86).
- **Seen FP:** function names as plain words ("system design") do not match. Added in D86.

### LOG-CMDI-SHELL
- **Matches (query only):** a shell separator (`;`, `|`, `` ` ``, `&&`, `$(`), then a probing command (`cat`, `id`, `whoami`, `uname`, `ls`, `curl`, `wget`, `nc`, `sleep`, `ping`, ...).
- **Severity / confidence:** high / medium. T1190, T1059.004.
- **Does not prove:** the command ran. A later write on the same endpoint is what makes it the root cause (D94).
- **Seen FP:** none on real evidence. On the fourth real case it adds background lines only; plain words ("cat pictures") and `a|b` tags do not match. Added in D94.

### LOG-SCANNER-UA
- **Matches (user agent):** sqlmap, nikto, nmap, acunetix, nessus, wpscan, masscan, dirbuster, gobuster, havij, commix, wfuzz, ffuf, nuclei.
- **Severity / confidence:** low / medium. T1595.002 (recon).
- **Does not prove:** anything beyond the tool's name, which anyone can set or hide.
- **Seen FP:** none. Hydra is left out on purpose: each brute-force attempt would become its own event (D88, D94).

### LOG-WEBSHELL-UPLOAD-DIR
- **Matches (path):** a script extension inside an upload or writable folder (`uploads`, `files`, `images`, ...).
- **Severity / confidence:** high / medium. T1505.003.
- **Does not prove:** a shell exists. A plain GET from a crawler or a curious visitor does not make that client an attacker (D55).
- **Seen FP:** bots probing such paths at scale (over 10,000 lines on the fourth real case), all kept as background. As a lead for a log-only shell, it also needs POSTs with varied answers (D95).

### LOG-WEBSHELL-CMD-PARAM
- **Matches (query):** `cmd=`, `exec=`, `command=`, `shell=` with a value.
- **Severity / confidence:** medium / low. T1505.003, T1059.
- **Does not prove:** a shell. It needs two different 2xx sizes on a script missing from the webroot to report one (D85, D89).
- **Seen FP:** one IP probing the same path on many virtual hosts, fixed by keying scripts by site (D89).

## File rules (`src/webforensics/detect/file_rules.py`)

Content is read as bytes from the evidence copy, at most 2 MiB, never executed (D15, D28). A file identical to its baseline copy gives no finding (D43, D94).

### FILE-WEBSHELL-WRITABLE-EXEC
- **Matches:** a script, by any extension part (`x.php.jpg`, trailing dots, D94), in an upload or writable folder.
- **Severity / confidence:** high / medium. T1505.003.
- **Does not prove:** malice: some plugins keep code under `uploads`.
- **Seen FP:** application installs that ship code in such folders, handled by deploy batches (D79, D84).

### FILE-WEBSHELL-REQUEST-EXEC
- **Matches:** `eval`, `assert`, `system`, `exec`, `shell_exec`, `passthru`, `popen` or `proc_open` fed by `$_GET`, `$_POST`, `$_REQUEST` or `$_COOKIE`.
- **Severity / confidence:** high / high. T1505.003, T1059.
- **Does not prove:** use. It is the one content rule that accuses a file even inside a deploy batch (D79).
- **Seen FP:** none known. Method calls (`->exec(`, `::exec(`) do not match.

### FILE-WEBSHELL-OBFUSCATION
- **Matches:** a long high-entropy token, or `base64_decode(`, `gzinflate(` or `str_rot13(`.
- **Severity / confidence:** low / low. T1027.
- **Does not prove:** anything alone; libraries embed encoded data.
- **Seen FP:** encoded test data in installs (D84), and WordPress core files (dropped when identical to the baseline, D94).

### FILE-DEFACEMENT-PAGE
- **Matches:** "hacked by", "has been defaced", "di-hack oleh" and similar, in an index page.
- **Severity / confidence:** high / medium. T1491.002.
- **Does not prove:** who wrote it. Added in D87.
- **Seen FP:** none.

### FILE-PERSISTENCE-ENTRYPOINT-CHANGE
- **Matches:** `.htaccess` or an index page that is new or changed against the baseline.
- **Severity / confidence:** low / low. T1505.003.
- **Does not prove:** persistence; sites edit these files.
- **Seen FP:** expected on any site update; it only leads, never accuses alone.

### FILE-HTACCESS-PHP-HANDLER
- **Matches:** a new or changed `.htaccess` that maps another extension to PHP (`AddType`, `AddHandler`, `SetHandler` inside or outside a `<FilesMatch>`).
- **Severity / confidence:** high / medium. T1505.003.
- **Does not prove:** use. Hosting panels that map PHP versions to `.php` give nothing. Added in D94.
- **Seen FP:** none; not exercised on v2, whose `.htaccess` is defanged.

### FILE-HANDLER-EXEC
- **Matches:** a non-script file that such an `.htaccess` makes executable.
- **Severity / confidence:** high / medium. T1505.003. Added in D94.
- **Seen FP:** none.

### FILE-ANTIFORENSICS-TIMESTOMP
- **Matches:** an mtime far older than the trusted change time (btime, ctime or the FIM alert).
- **Severity / confidence:** medium / medium. T1070.006.
- **Does not prove:** forgery: copies and archives keep old mtimes, which the report says (D10, D41, D84).
- **Seen FP:** files extracted from archives on Windows (D84).

### FILE-WAZUH-FIM-OUTSIDE-DOCROOT
- **Matches:** Wazuh FIM changes outside the docroot (for example `/etc/cron.d`) in the analyzed window.
- **Severity / confidence:** low / low (persistence category). Shown for review, not tied to the web incident (D80).
- **Seen FP:** system updates.

## Correlation findings (`src/webforensics/correlate/`)

These fire only from two pieces of evidence together.

### CORR-LONELY-EXEC-WRITE
- **Matches:** a code file without a baseline, written alone (outside any batch of more than two files).
- **Severity / confidence:** medium / low. T1505.003.
- **Does not prove:** an attack: it joins the incident only when a request plausibly wrote it (D49).
- **Seen FP:** cache files, which go to review instead (D56).

### CORR-RARE-POST-TARGET
- **Matches:** a file POSTed to by at most two clients, with at most 20 hits in all.
- **Severity / confidence:** medium / low. T1505.003.
- **Does not prove:** a shell; a little-used form looks the same (D49).
- **Seen FP:** none known.

### CORR-SQLI-LOGIN-BYPASS
- **Matches:** an SQL-injection login attempt whose answer looks like a success, from a client outside the incident.
- **Severity / confidence:** high / medium. T1190.
- **Does not prove:** a compromise. Nobody is accused, but the login must be fixed (D71).
- **Seen FP:** none known.

### CORR-STATIC-FILE-EXECUTED
- **Matches:** a new or changed non-script file reached by a POST answered 2xx with a size unlike its own.
- **Severity / confidence:** high / medium. T1505.003.
- **Does not prove:** what ran. It catches an image run as PHP even when the `.htaccess` is not in the evidence (D94).
- **Seen FP:** none known. Compression or range answers could differ in size; they would also need a POST.

## Correlation patterns without a finding id

Some conclusions come from the engine's steps, not from a rule id. Each is in the decision log:
- the writing request is ranked by closeness to the file's birth (D54, D69);
- the entry point is a login only after failed tries or an SQLi bypass; a clean login is valid-account abuse and the write is the root cause (D38, D94);
- an attacked endpoint that then writes (D94);
- non-code files written in an attacker's second (D94);
- log-only scripts (D85, D89, D94, D95);
- deploy batches and app-generated files go to review (D56, D79).
