"""Write a report's conclusions back to Wazuh as events (M6+ write-back, D92).

`build_events` turns a report into small, flat events: one summary per case, one per
affected file, one per attacker IP. Each is a JSON object with
`"integration": "webforensics"`, which the built-in JSON decoder decodes and the rules in
`lab/wazuh/rules/webforensics_rules.xml` match. `queue.py` sends them. The same report
gives the same events.
"""

import json
from pathlib import Path
from typing import Any

from webforensics.adapters.wazuh.queue import INTEGRATION
from webforensics.models import CitationKind, Report

MAX_LISTED = 20  # attacker IPs and files named inside the summary event


def _root(report: Report) -> dict[str, str] | None:
    cause = report.result.root_cause
    if cause is None:
        return None
    event = next(e for e in report.result.timeline if e.event_id == cause.event_id)
    params = event.description.params
    line = next((c for c in event.citations if c.kind is not CitationKind.FILE), None)
    return {
        "time": event.ts.isoformat(),
        "method": params.get("method", ""),
        "path": params.get("path", ""),
        "status": params.get("status", ""),
        "actor": event.actor or "",
        "vuln_class": cause.vuln_class or "unknown",
        "confidence": cause.confidence.value,
        "evidence": f"{line.source}:{line.line_no}" if line and line.line_no else "",
    }


def build_events(report: Report, report_sha256: str | None = None) -> list[dict[str, Any]]:
    """The events for one report, summary first. Values are strings (or lists of strings)
    so that rule `<field>` matches and dashboards treat them the same way."""
    result = report.result
    compromised = bool(result.affected_files or result.log_only_files)
    files = [f.path for f in result.affected_files] + list(result.log_only_files)
    common = {"case_id": report.case.case_id, "tool_version": report.run.tool_version}
    if report_sha256:
        common["report_sha256"] = report_sha256
    root = _root(report)
    summary: dict[str, Any] = {
        "type": "summary",
        **common,
        "compromised": "yes" if compromised else "no",
        "root_cause_found": "yes" if root else "no",
        "affected_files": str(len(files)),
        "attackers": str(len(result.iocs.ips)),
        "gaps": str(len(result.gaps)),
        "attacker_ips": list(result.iocs.ips[:MAX_LISTED]),
        "files": files[:MAX_LISTED],
    }
    if report.scope.log_first and report.scope.log_last:
        summary["log_first"] = report.scope.log_first.isoformat()
        summary["log_last"] = report.scope.log_last.isoformat()
    if root:
        summary["root_cause"] = root
    events = [summary]
    for file in result.affected_files:
        events.append({"type": "affected_file", **common, "path": file.path,
                       "sha256": file.sha256, "status": file.baseline_status.value,
                       "urls": list(file.url_paths)})
    for path in result.log_only_files:
        events.append({"type": "affected_file", **common, "path": path, "sha256": "",
                       "status": "log_only", "urls": []})
    for ip in result.iocs.ips:
        events.append({"type": "attacker_ip", **common, "ip": ip})
    return [{"integration": INTEGRATION, INTEGRATION: e} for e in events]


def write_jsonl(events: list[dict[str, Any]], path: Path) -> None:
    """The same events as JSON lines, for inspection or a `<localfile>` with json format."""
    lines = [json.dumps(e, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
             for e in events]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
