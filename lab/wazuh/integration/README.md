# Installing the trigger and write-back on a Wazuh manager (M6+)

These are the steps that ran end to end on the lab manager (Wazuh 4.14.9, Amazon Linux 2023 image) on 2026-11-01; the result is in [docs/wazuh-notes.md](../../../docs/wazuh-notes.md) section 11 and D92. Run them as root on the manager.

1. **Python 3.11 and the tool.** Wazuh 4.14 bundles Python 3.10, and webforensics needs 3.11+, so it gets its own virtual environment:
   ```sh
   dnf install -y python3.11 python3.11-pip
   python3.11 -m venv /opt/webforensics/venv
   /opt/webforensics/venv/bin/pip install webforensics-0.1.0-py3-none-any.whl   # built with `pip wheel .`
   ```
2. **Wrapper, rules and config.**
   ```sh
   install -o root  -g wazuh -m 750 custom-webforensics       /var/ossec/integrations/custom-webforensics
   install -o wazuh -g wazuh -m 660 ../rules/webforensics_rules.xml /var/ossec/etc/rules/webforensics_rules.xml
   mkdir -p /var/ossec/etc/webforensics /var/ossec/logs/webforensics
   install -o root  -g wazuh -m 640 trigger.json              /var/ossec/etc/webforensics/trigger.json
   install -o root  -g wazuh -m 640 reader.pass               /var/ossec/etc/webforensics/reader.pass
   chown wazuh:wazuh /var/ossec/logs/webforensics
   ```
   Start `trigger.json` from [trigger.example.json](trigger.example.json): the indexer URL and CA as the manager sees them, the read-only indexer user (read on `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*`, as for `pull`), and one entry per web server agent with its docroot and log paths as Wazuh `location`s. `reader.pass` holds only that user's password.
3. **Integration blocks.** Add the two blocks from [ossec-integration.xml](ossec-integration.xml) inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`, then `/var/ossec/bin/wazuh-control restart`. `ossec.log` should show "Enabling integration for: 'custom-webforensics'" twice.
4. **Check.** The integration runs as the `wazuh` user, so check as that user:
   ```sh
   sudo -u wazuh /opt/webforensics/venv/bin/python -c "from pathlib import Path; from webforensics.adapters.wazuh.trigger import TriggerConfig; print(TriggerConfig.load(Path('/var/ossec/etc/webforensics/trigger.json')).sites)"
   ```

After that, a FIM change in a configured docroot (or a web-attack alert on a configured access log) starts one analysis per agent per cool-down. Each case lands in `/var/ossec/logs/webforensics/cases/<time>-<agent id>/` (recording, report, viewer, write-back events), `trigger.log` records each start and finish, and the conclusions appear as alerts 100801–100806 under the web server's agent.

To send the conclusions of a report made by hand: `webforensics writeback report.json --socket /var/ossec/queue/sockets/queue --agent-id 001 --agent-name web01`.
