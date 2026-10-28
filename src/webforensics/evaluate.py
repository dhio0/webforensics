"""Score the analyzer against benchmark ground truth (`webforensics eval`).

Each scenario folder holds `ground_truth.json` and `evidence/`. The analysis runs exactly
as `analyze` would, then its result is compared with what the replay is known to have
done. Metrics (docs/evaluation.md):

- step recall: attack steps whose log line is cited somewhere in the timeline;
- root cause: correct, only among the alternatives, wrong, missed, or a false root
  (a root cause reported for a scenario with no compromise);
- false accusations: reported attacker IPs and affected files that are not in the
  ground truth (precision = correct / reported);
- expected rules: rule ids that must be reported (e.g. timestomp);
- runtime: wall time of load + correlate (not deterministic, reported apart).
"""

import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from webforensics.analysis import EvidenceInputs, load_evidence
from webforensics.correlate import CorrelationConfig, correlate
from webforensics.models import CitationKind, CorrelationResult
from webforensics.parsers.error_log import ErrorLogFormat


class RootVerdict(StrEnum):
    CORRECT = "correct"
    ALTERNATIVE = "alternative"  # right request, but only as an alternative candidate
    WRONG = "wrong"
    MISSED = "missed"  # ground truth has a root cause, the tool reported none
    FALSE_ROOT = "false_root"  # no compromise, yet a root cause was reported


@dataclass(frozen=True)
class ScenarioScore:
    scenario_id: str
    split: str
    steps_expected: int
    steps_found: int
    missed_steps: tuple[str, ...]
    root: RootVerdict
    attacker_ips: int
    reported_ips: int
    false_ips: tuple[str, ...]
    truth_files: int
    reported_files: int
    false_files: tuple[str, ...]
    missed_files: tuple[str, ...]
    rules_expected: tuple[str, ...]
    missed_rules: tuple[str, ...]
    runtime_s: float = field(compare=False)

    @property
    def step_recall(self) -> float | None:
        return self.steps_found / self.steps_expected if self.steps_expected else None

    @property
    def false_accusations(self) -> int:
        return len(self.false_ips) + len(self.false_files)

    @property
    def passed(self) -> bool:
        return (self.root is RootVerdict.CORRECT and not self.missed_steps
                and self.false_accusations == 0 and not self.missed_files
                and not self.missed_rules)


def _expected(step: dict) -> bool:
    return step.get("expected_in_timeline", step["category"] != "benign_request")


def scenario_inputs(folder: Path, truth: dict) -> tuple[EvidenceInputs, CorrelationConfig]:
    """The analysis a scenario asks for, with names relative to its evidence folder."""
    evidence = folder / "evidence"
    spec = truth.get("analysis", {})
    inputs = EvidenceInputs(
        logs=tuple(evidence / p for p in spec.get("access_logs", ["access.log"])),
        manifest=evidence / spec.get("manifest", "manifest.tsv"),
        baseline=evidence / spec["baseline"] if "baseline" in spec else None,
        error_logs=tuple(evidence / p for p in spec.get("error_logs", [])),
        error_format=ErrorLogFormat(spec.get("error_log_format", "nginx")),
        error_utc_offset=spec.get("error_log_utc_offset", "+0000"),
        base_dir=evidence,
    )
    config = CorrelationConfig(trusted_proxies=tuple(spec.get("trusted_proxies", ())))
    return inputs, config


def _cited_lines(result: CorrelationResult) -> set[tuple[str, int]]:
    return {(c.source, c.line_no) for e in result.timeline for c in e.citations
            if c.kind is CitationKind.LOG_LINE and c.line_no is not None}


def _event_lines(result: CorrelationResult, event_id: str) -> set[tuple[str, int]]:
    event = next(e for e in result.timeline if e.event_id == event_id)
    return {(c.source, c.line_no) for c in event.citations
            if c.kind is CitationKind.LOG_LINE and c.line_no is not None}


def root_verdict(truth: dict, result: CorrelationResult) -> RootVerdict:
    root_id = truth.get("root_cause_step")
    if root_id is None:
        return RootVerdict.CORRECT if result.root_cause is None else RootVerdict.FALSE_ROOT
    if result.root_cause is None:
        return RootVerdict.MISSED
    step = next(s for s in truth["steps"] if s["id"] == root_id)
    line = (step["log_file"], step["line_no"])
    if line in _event_lines(result, result.root_cause.event_id):
        return RootVerdict.CORRECT
    if any(line in _event_lines(result, alt) for alt in result.root_cause.alternative_event_ids):
        return RootVerdict.ALTERNATIVE
    return RootVerdict.WRONG


def score(truth: dict, result: CorrelationResult, runtime_s: float) -> ScenarioScore:
    cited = _cited_lines(result)
    expected = [s for s in truth["steps"] if _expected(s)]
    missed = tuple(s["id"] for s in expected if (s["log_file"], s["line_no"]) not in cited)
    attackers = set(truth["attacker_ips"])
    truth_files = {f["path"] for f in truth["files"]}
    reported_files = {f.path for f in result.affected_files}
    reported_rules = {f.rule_id for f in result.findings}
    rules = tuple(truth.get("expected_rule_ids", ()))
    return ScenarioScore(
        scenario_id=truth["scenario_id"], split=truth.get("split", "dev"),
        steps_expected=len(expected), steps_found=len(expected) - len(missed),
        missed_steps=missed, root=root_verdict(truth, result),
        attacker_ips=len(attackers), reported_ips=len(result.iocs.ips),
        false_ips=tuple(sorted(set(result.iocs.ips) - attackers)),
        truth_files=len(truth_files), reported_files=len(reported_files),
        false_files=tuple(sorted(reported_files - truth_files)),
        missed_files=tuple(sorted(truth_files - reported_files)),
        rules_expected=rules, missed_rules=tuple(r for r in rules if r not in reported_rules),
        runtime_s=runtime_s,
    )


def evaluate_scenario(folder: Path) -> ScenarioScore:
    truth = json.loads((folder / "ground_truth.json").read_text(encoding="utf-8"))
    inputs, config = scenario_inputs(folder, truth)
    start = time.perf_counter()
    evidence = load_evidence(inputs)
    result = correlate(evidence.logs, evidence.files, baseline=evidence.baseline,
                       config=config)
    return score(truth, result, time.perf_counter() - start)


def scenario_folders(benchmark: Path, only: tuple[str, ...] = ()) -> list[Path]:
    folders = sorted(p.parent for p in (benchmark / "scenarios").glob("*/ground_truth.json"))
    if only:
        known = {p.name for p in folders}
        unknown = sorted(set(only) - known)
        if unknown:
            raise ValueError(f"unknown scenario(s): {', '.join(unknown)}")
        folders = [p for p in folders if p.name in only]
    if not folders:
        raise ValueError(f"no scenarios found under {benchmark / 'scenarios'}")
    return folders


# --- Reporting -----------------------------------------------------------------------------


def _ratio(found: int, total: int) -> str:
    return f"{found}/{total}" if total else "-"


def _precision(reported: int, false: int) -> str:
    return f"{(reported - false) / reported:.2f}" if reported else "-"


def totals(scores: list[ScenarioScore]) -> dict[str, object]:
    steps = sum(s.steps_expected for s in scores)
    found = sum(s.steps_found for s in scores)
    reported = sum(s.reported_ips + s.reported_files for s in scores)
    false = sum(s.false_accusations for s in scores)
    return {
        "scenarios": len(scores),
        "passed": sum(s.passed for s in scores),
        "step_recall": round(found / steps, 4) if steps else None,
        "root_cause_correct": sum(s.root is RootVerdict.CORRECT for s in scores),
        "false_accusations": false,
        "accusation_precision": round((reported - false) / reported, 4) if reported else None,
    }


def markdown_table(scores: list[ScenarioScore], *, runtime: bool = True) -> str:
    """README-ready results. `runtime=False` gives a deterministic table."""
    head = ["Scenario", "Split", "Step recall", "Root cause", "False IPs", "False files",
            "IP precision", "File precision", "Expected rules", "Code line"]
    if runtime:
        head.append("Runtime")
    rows = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for s in scores:
        cells = [s.scenario_id.upper(), s.split, _ratio(s.steps_found, s.steps_expected),
                 s.root.value, str(len(s.false_ips)), str(len(s.false_files)),
                 _precision(s.reported_ips, len(s.false_ips)),
                 _precision(s.reported_files, len(s.false_files)),
                 _ratio(len(s.rules_expected) - len(s.missed_rules), len(s.rules_expected)),
                 "n/a (M7)"]
        if runtime:
            cells.append(f"{s.runtime_s:.2f} s")
        rows.append("| " + " | ".join(cells) + " |")
    lines = ["\n".join(rows), ""]
    for split in ("dev", "held_out"):
        group = [s for s in scores if s.split == split]
        if group:
            t = totals(group)
            recall = f"{t['step_recall']:.2f}" if t["step_recall"] is not None else "-"
            lines.append(f"**{split}**: {t['passed']}/{t['scenarios']} scenarios fully "
                         f"correct, step recall {recall}, root cause "
                         f"{t['root_cause_correct']}/{t['scenarios']}, "
                         f"false accusations {t['false_accusations']}.")
    return "\n".join(lines).rstrip() + "\n"


def details(scores: list[ScenarioScore]) -> list[str]:
    """What went wrong, per scenario, so a failure can be traced."""
    out = []
    for s in scores:
        problems = [f"missed steps: {', '.join(s.missed_steps)}" if s.missed_steps else "",
                    f"root cause: {s.root.value}" if s.root is not RootVerdict.CORRECT else "",
                    f"false IPs: {', '.join(s.false_ips)}" if s.false_ips else "",
                    f"false files: {', '.join(s.false_files)}" if s.false_files else "",
                    f"missed files: {', '.join(s.missed_files)}" if s.missed_files else "",
                    f"missed rules: {', '.join(s.missed_rules)}" if s.missed_rules else ""]
        problems = [p for p in problems if p]
        if problems:
            out.append(f"{s.scenario_id.upper()}: " + "; ".join(problems))
    return out


def to_json(scores: list[ScenarioScore]) -> dict[str, object]:
    def one(s: ScenarioScore) -> dict[str, object]:
        return {
            "scenario_id": s.scenario_id, "split": s.split, "passed": s.passed,
            "step_recall": s.step_recall, "steps_expected": s.steps_expected,
            "missed_steps": list(s.missed_steps), "root_cause": s.root.value,
            "false_ips": list(s.false_ips), "false_files": list(s.false_files),
            "missed_files": list(s.missed_files), "missed_rules": list(s.missed_rules),
            "runtime_s": round(s.runtime_s, 3),
        }
    return {"scenarios": [one(s) for s in scores],
            "totals": {split: totals([s for s in scores if s.split == split])
                       for split in ("dev", "held_out")
                       if any(s.split == split for s in scores)}}
