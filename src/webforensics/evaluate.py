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

A scenario with `evidence/wazuh/recording.jsonl` (recorded in the same replay as the file
evidence) is scored a second time through the WazuhAdapter. Its citations point at lines
of the recording, so they are mapped back to the access/error-log lines that hold the same
text before scoring; the ground truth is the same for both adapters.
"""

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from webforensics.adapters.wazuh.recording import Stream, read_recording
from webforensics.analysis import EvidenceInputs, load_evidence
from webforensics.codeloc.locate import review_code
from webforensics.correlate import CorrelationConfig, correlate
from webforensics.models import CitationKind, CodeLocation, CorrelationResult
from webforensics.parsers.error_log import ErrorLogFormat

ADAPTERS = ("file", "wazuh")
RECORDING = "wazuh/recording.jsonl"
LineMap = dict[tuple[str, int], tuple[str, int]]


class RootVerdict(StrEnum):
    CORRECT = "correct"
    ALTERNATIVE = "alternative"  # right request, but only as an alternative candidate
    WRONG = "wrong"
    MISSED = "missed"  # ground truth has a root cause, the tool reported none
    FALSE_ROOT = "false_root"  # no compromise, yet a root cause was reported


class CodeVerdict(StrEnum):
    CORRECT = "correct"  # a finding at the ground-truth file and line
    WRONG = "wrong"  # findings, none at that line
    MISSED = "missed"  # no finding in that file
    NOT_LOCALIZED = "n/a"  # a weakness class the tool does not localize yet
    NONE = "-"  # the scenario has no vulnerable code (no compromise)


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
    adapter: str = "file"
    code_line: CodeVerdict = CodeVerdict.NONE

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
                and not self.missed_rules
                and self.code_line in (CodeVerdict.CORRECT, CodeVerdict.NOT_LOCALIZED,
                                       CodeVerdict.NONE))


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
        # The app's code, copied only where it hashes to the manifest (M7 analyzes it).
        webroot=evidence / "webroot" if (evidence / "webroot").is_dir() else None,
    )
    config = CorrelationConfig(trusted_proxies=tuple(spec.get("trusted_proxies", ())))
    return inputs, config


def _lines(citations, line_map: LineMap | None) -> set[tuple[str, int]]:
    found = {(c.source, c.line_no) for c in citations
             if c.kind is CitationKind.LOG_LINE and c.line_no is not None}
    return {line_map.get(line, line) for line in found} if line_map else found


def _cited_lines(result: CorrelationResult,
                 line_map: LineMap | None = None) -> set[tuple[str, int]]:
    return _lines([c for e in result.timeline for c in e.citations], line_map)


def _event_lines(result: CorrelationResult, event_id: str,
                 line_map: LineMap | None = None) -> set[tuple[str, int]]:
    event = next(e for e in result.timeline if e.event_id == event_id)
    return _lines(event.citations, line_map)


def _log_lines(path: Path) -> list[str]:
    """Physical lines decoded like the log parsers do, so they compare with `full_log`."""
    raw = path.read_bytes().split(b"\n")
    if raw and raw[-1] == b"":
        raw.pop()
    return [line.rstrip(b"\r").decode("utf-8", "backslashreplace") for line in raw]


def recording_line_map(folder: Path, truth: dict) -> LineMap:
    """(recording, line) -> (log file, line) for every web event whose text is a line of
    the scenario's own log files. Repeated lines are matched in order."""
    evidence = folder / "evidence"
    header, hits = read_recording(evidence / RECORDING)
    spec = truth.get("analysis", {})
    names = dict(zip(header.access_logs, spec.get("access_logs", ["access.log"]), strict=False))
    names |= dict(zip(header.error_logs, spec.get("error_logs", []), strict=False))
    free: dict[tuple[str, str], deque[int]] = defaultdict(deque)
    for name in set(names.values()):
        for line_no, text in enumerate(_log_lines(evidence / name), start=1):
            free[(name, text)].append(line_no)
    mapping: LineMap = {}
    for hit in hits:
        name = names.get(str(hit.source.get("location")))
        key = (name or "", str(hit.source.get("full_log")))
        if hit.stream is Stream.WEB and free.get(key):
            mapping[(RECORDING, hit.line_no)] = (key[0], free[key].popleft())
    return mapping


def root_verdict(truth: dict, result: CorrelationResult,
                 line_map: LineMap | None = None) -> RootVerdict:
    root_id = truth.get("root_cause_step")
    if root_id is None:
        return RootVerdict.CORRECT if result.root_cause is None else RootVerdict.FALSE_ROOT
    if result.root_cause is None:
        return RootVerdict.MISSED
    step = next(s for s in truth["steps"] if s["id"] == root_id)
    line = (step["log_file"], step["line_no"])
    if line in _event_lines(result, result.root_cause.event_id, line_map):
        return RootVerdict.CORRECT
    if any(line in _event_lines(result, alt, line_map)
           for alt in result.root_cause.alternative_event_ids):
        return RootVerdict.ALTERNATIVE
    return RootVerdict.WRONG


LOCALIZED = frozenset({"sql_injection"})


def code_verdict(truth: dict, findings: tuple[CodeLocation, ...]) -> CodeVerdict:
    spec = truth.get("vulnerable_code")
    if not spec:
        return CodeVerdict.NONE
    if spec.get("vuln_class") not in LOCALIZED:
        return CodeVerdict.NOT_LOCALIZED
    path = Path(spec["file"]).relative_to("lab/app").as_posix()
    in_file = [f for f in findings if f.file == path]
    if any(f.line == spec["line"] for f in in_file):
        return CodeVerdict.CORRECT
    return CodeVerdict.WRONG if in_file else CodeVerdict.MISSED


def score(truth: dict, result: CorrelationResult, runtime_s: float,
          line_map: LineMap | None = None, adapter: str = "file",
          code: tuple[CodeLocation, ...] = ()) -> ScenarioScore:
    cited = _cited_lines(result, line_map)
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
        missed_steps=missed, root=root_verdict(truth, result, line_map),
        attacker_ips=len(attackers), reported_ips=len(result.iocs.ips),
        false_ips=tuple(sorted(set(result.iocs.ips) - attackers)),
        truth_files=len(truth_files), reported_files=len(reported_files),
        false_files=tuple(sorted(reported_files - truth_files)),
        missed_files=tuple(sorted(truth_files - reported_files)),
        rules_expected=rules, missed_rules=tuple(r for r in rules if r not in reported_rules),
        runtime_s=runtime_s, adapter=adapter, code_line=code_verdict(truth, code),
    )


def available_adapters(folder: Path) -> tuple[str, ...]:
    return ADAPTERS if (folder / "evidence" / RECORDING).is_file() else ("file",)


def evaluate_scenario(folder: Path, adapter: str = "file") -> ScenarioScore:
    truth = json.loads((folder / "ground_truth.json").read_text(encoding="utf-8"))
    inputs, config = scenario_inputs(folder, truth)
    line_map = None
    if adapter == "wazuh":
        inputs = EvidenceInputs(wazuh_recording=folder / "evidence" / RECORDING,
                                error_format=inputs.error_format,
                                error_utc_offset=inputs.error_utc_offset,
                                base_dir=inputs.base_dir, webroot=inputs.webroot)
        line_map = recording_line_map(folder, truth)
    elif adapter != "file":
        raise ValueError(f"unknown adapter: {adapter}")
    start = time.perf_counter()
    evidence = load_evidence(inputs)
    result = correlate(evidence.logs, evidence.files, baseline=evidence.baseline,
                       config=config)
    code, _ = review_code(result, evidence.files, inputs.webroot, inputs.url_prefix)
    return score(truth, result, time.perf_counter() - start, line_map, adapter, code)


def evaluate_all(folders: list[Path], adapters: tuple[str, ...] = ADAPTERS
                 ) -> list[ScenarioScore]:
    """Every folder through every requested adapter it has evidence for."""
    return [evaluate_scenario(folder, adapter) for folder in folders
            for adapter in adapters if adapter in available_adapters(folder)]


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
    head = ["Scenario", "Adapter", "Split", "Step recall", "Root cause", "False IPs", "False files",
            "IP precision", "File precision", "Expected rules", "Code line"]
    if runtime:
        head.append("Runtime")
    rows = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for s in scores:
        cells = [s.scenario_id.upper(), s.adapter, s.split,
                 _ratio(s.steps_found, s.steps_expected),
                 s.root.value, str(len(s.false_ips)), str(len(s.false_files)),
                 _precision(s.reported_ips, len(s.false_ips)),
                 _precision(s.reported_files, len(s.false_files)),
                 _ratio(len(s.rules_expected) - len(s.missed_rules), len(s.rules_expected)),
                 s.code_line.value]
        if runtime:
            cells.append(f"{s.runtime_s:.2f} s")
        rows.append("| " + " | ".join(cells) + " |")
    lines = ["\n".join(rows), ""]
    for adapter, split in _groups(scores):
        group = [s for s in scores if s.split == split and s.adapter == adapter]
        if group:
            t = totals(group)
            recall = f"{t['step_recall']:.2f}" if t["step_recall"] is not None else "-"
            lines.append(f"**{adapter}, {split}**: {t['passed']}/{t['scenarios']} "
                         "scenarios fully "
                         f"correct, step recall {recall}, root cause "
                         f"{t['root_cause_correct']}/{t['scenarios']}, "
                         f"false accusations {t['false_accusations']}.")
    return "\n".join(lines).rstrip() + "\n"


def _groups(scores: list[ScenarioScore]) -> list[tuple[str, str]]:
    return [(a, s) for a in ADAPTERS for s in ("dev", "held_out")
            if any(x.adapter == a and x.split == s for x in scores)]


def details(scores: list[ScenarioScore]) -> list[str]:
    """What went wrong, per scenario, so a failure can be traced."""
    out = []
    for s in scores:
        problems = [f"missed steps: {', '.join(s.missed_steps)}" if s.missed_steps else "",
                    f"root cause: {s.root.value}" if s.root is not RootVerdict.CORRECT else "",
                    f"false IPs: {', '.join(s.false_ips)}" if s.false_ips else "",
                    f"false files: {', '.join(s.false_files)}" if s.false_files else "",
                    f"missed files: {', '.join(s.missed_files)}" if s.missed_files else "",
                    f"missed rules: {', '.join(s.missed_rules)}" if s.missed_rules else "",
                    f"code line: {s.code_line.value}" if s.code_line in (
                        CodeVerdict.WRONG, CodeVerdict.MISSED) else ""]
        problems = [p for p in problems if p]
        if problems:
            label = s.scenario_id.upper() + ("" if s.adapter == "file" else f" ({s.adapter})")
            out.append(f"{label}: " + "; ".join(problems))
    return out


def to_json(scores: list[ScenarioScore]) -> dict[str, object]:
    def one(s: ScenarioScore) -> dict[str, object]:
        return {
            "scenario_id": s.scenario_id, "adapter": s.adapter, "split": s.split,
            "passed": s.passed,
            "step_recall": s.step_recall, "steps_expected": s.steps_expected,
            "missed_steps": list(s.missed_steps), "root_cause": s.root.value,
            "false_ips": list(s.false_ips), "false_files": list(s.false_files),
            "missed_files": list(s.missed_files), "missed_rules": list(s.missed_rules),
            "code_line": s.code_line.value,
            "runtime_s": round(s.runtime_s, 3),
        }
    totals_by: dict[str, dict[str, object]] = defaultdict(dict)
    for adapter, split in _groups(scores):
        totals_by[adapter][split] = totals([s for s in scores
                                            if s.adapter == adapter and s.split == split])
    return {"scenarios": [one(s) for s in scores], "totals": dict(totals_by)}
