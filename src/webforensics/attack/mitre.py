"""The small set of ATT&CK techniques the tool can emit, with their primary tactic.

Kept as a static table so reports are reproducible and work offline. Technique names
follow ATT&CK Enterprise; only the tactic we use for the timeline phase is listed.
"""

from typing import NamedTuple


class Technique(NamedTuple):
    technique_id: str
    name: str
    tactic: str


TECHNIQUES: dict[str, Technique] = {
    t.technique_id: t
    for t in (
        Technique("T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance"),
        Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
        Technique("T1078", "Valid Accounts", "Initial Access"),
        Technique("T1505.003", "Server Software Component: Web Shell", "Persistence"),
        Technique("T1059", "Command and Scripting Interpreter", "Execution"),
        Technique("T1083", "File and Directory Discovery", "Discovery"),
        Technique("T1027", "Obfuscated Files or Information", "Defense Evasion"),
        Technique("T1070.006", "Indicator Removal: Timestomp", "Defense Evasion"),
        Technique("T1070.004", "Indicator Removal: File Deletion", "Defense Evasion"),
        Technique("T1491.002", "Defacement: External Defacement", "Impact"),
    )
}


def tactic_for(technique_id: str | None) -> str | None:
    if technique_id is None:
        return None
    technique = TECHNIQUES.get(technique_id)
    return technique.tactic if technique else None
