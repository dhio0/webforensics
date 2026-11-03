# Evidence from Wazuh

If the web server runs a Wazuh 4.x agent with FIM on the webroot, the evidence can come from the Wazuh indexer instead of the server. `pull` is the only command that uses the network. It copies one agent's web log lines and FIM alerts for a time window into a recording, and analysis then runs offline on that file:
```bash
export WF_WAZUH_USER=webforensics_reader WF_WAZUH_PASSWORD=...   # or --password-file
webforensics pull --indexer https://wazuh-indexer:9200 --ca-cert root-ca.pem   --agent web01 --since 2026-10-29T08:00:00+07:00 --docroot /var/www/html   --access-log /var/log/nginx/access.log --error-log /var/log/nginx/error.log --out case01.jsonl
webforensics analyze --wazuh-recording case01.jsonl --out case01/report
```
- Web events come from `wazuh-archives-4.x-*`, because ordinary requests (including a successful upload) never become Wazuh alerts. Archives are off by default in Wazuh; without them, `pull` falls back to alerts and the report marks the log as partial.
- The raw line in `full_log` goes through the same parser as plain log files, so both adapters judge requests the same way. Citations point at lines of the recording (`case01.jsonl:17`).
- Realtime FIM gives the write time (an upper bound, a second or two after the write), so the tool also catches a forged mtime. FIM gives hashes, not file content; `--webroot` adds content, used only where its SHA-256 matches FIM.
- TLS is always verified (`--tls-server-name` when the certificate name differs from the URL host), and the password is never accepted on the command line.

In the lab (Wazuh 4.14.9), all five scenarios were replayed with Wazuh on, and the evidence from that same run was analyzed through both adapters. Root cause, affected files and attacker IPs were identical in every scenario (`tests/integration/test_wazuh_lab.py`, marked `lab`). Building that test exposed two problems: a deploy inside the pull window made every new app file look like an attack (now held to the same standard as lonely writes, D79), and FIM misses a file written while the agent restarts. That blind spot is a limitation of FIM itself; the report states it. Details: [docs/wazuh-notes.md](wazuh-notes.md).

## Automatic trigger and write-back
The tool can also run by itself when Wazuh sees something, and send its conclusions back as Wazuh alerts:
- **Trigger.** A custom integration, `custom-webforensics` ([lab/wazuh/integration/](../lab/wazuh/integration/)), receives FIM alerts and web-attack alerts (rules 31103–31106, 31164/31165/31170/31171). It starts an analysis only for a file change inside a configured docroot or an attack on a configured access log, at most once per agent per cool-down, and never for its own alerts. A detached worker pulls the window from the indexer, analyzes it, and writes the report and viewer into a case folder.
- **Write-back.** `webforensics writeback report.json --socket /var/ossec/queue/sockets/queue` (or the worker) sends one summary event, one per affected file and one per attacker IP to the manager's queue, the way Wazuh's own integrations do. Rules 100800–100806 ([lab/wazuh/rules/webforensics_rules.xml](../lab/wazuh/rules/webforensics_rules.xml)) turn them into alerts under the web server's agent, for example level 12: *"webforensics: website compromise reconstructed, entry GET /admin/login.php (sql_injection_auth_bypass, confidence medium), 1 affected file(s)"*.

Run end to end on the lab (Wazuh 4.14.9, scenario F): the realtime FIM alert for the uploaded file started one analysis; 46 seconds later Wazuh showed *website compromise reconstructed, entry GET /admin/login.php*, the affected file and the attacker IP under the web server's agent, matching the scenario's ground truth, and the write-back alerts did not start another analysis. Setup steps: [lab/wazuh/integration/README.md](../lab/wazuh/integration/README.md); details: D92 and [docs/wazuh-notes.md](wazuh-notes.md) section 11.
