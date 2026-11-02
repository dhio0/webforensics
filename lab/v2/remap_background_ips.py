"""Apply and verify the approved round-eight address-only evidence correction.

No network, replay, Docker, restore, or analysis is performed. The Git revision
must name the evidence immediately before the remap; its logs are read in memory.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from . import background, label, self_check

OLD_POOL = ipaddress.ip_network("10.0.0.0/8")
ADDRESS = re.compile(rb"(?<![\d.])10\.(?:\d{1,3}\.){2}\d{1,3}(?![\d.])")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def mapping_from_inputs(replay: Path, seed: int, output: Path) -> None:
    """Run exactly the production mapper over the recorded replay input."""
    mapper = background.IPMapper(seed)
    with gzip.open(replay / "background.log.gz", "rt", encoding="utf-8") as handle:
        for line in handle:
            row = background.parse_line(line, "")
            if row is None:
                raise ValueError("invalid recorded background input")
            mapper.assign(row["ip"])
    mapper.write_tsv(output)


def leftovers(scenario: Path) -> list[dict]:
    """Inventory every remaining old-range literal, including gzip contents."""
    found = []
    for path in sorted(scenario.rglob("*")):
        if not path.is_file() or path.name.endswith(".enc"):
            continue
        data = path.read_bytes()
        if path.suffix == ".gz":
            data = gzip.decompress(data)
        for address in sorted(set(ADDRESS.findall(data))):
            ipaddress.ip_address(address.decode())
            relative = path.relative_to(scenario).as_posix()
            if relative == "replay/ip-remap.json":
                reason = "Historical range and leftover inventory metadata; not a client"
            else:
                # These recordings should contain no other old-range literals.
                # A future non-client finding needs an explicit reviewed exception.
                raise ValueError(f"unreviewed old-range literal in {relative}")
            found.append({"file": relative, "address": address.decode(), "reason": reason})
    return found


def remap(root: Path, scenario_id: str, revision: str, apply: bool) -> dict:
    scenario = root / "benchmark/v2" / scenario_id
    replay = scenario / "replay"

    def original(relative: str) -> bytes:
        return subprocess.check_output([
            "git", "show", f"{revision}:benchmark/v2/{scenario_id}/{relative}"
        ], cwd=root)

    old_map = original("replay/ip_map.tsv")
    rows = old_map.decode().splitlines()
    seed = int(rows[0].split("=", 1)[1])
    mapper = background.IPMapper(seed)
    changes = {}
    for row in rows[2:]:
        source, old = row.split("\t")
        new = mapper.assign(source)
        if ipaddress.ip_address(old) in OLD_POOL:
            changes[old.encode()] = new.encode()
        else:
            assert new == old, "documentation-range mapping changed"
    assert len(set(changes.values())) == len(changes)
    with tempfile.TemporaryDirectory(prefix="round8-map-") as temp:
        ordered = Path(temp) / "ordered.tsv"
        actual = Path(temp) / "from-inputs.tsv"
        mapper.write_tsv(ordered)
        mapping_from_inputs(replay, seed, actual)
        new_map = ordered.read_bytes()
        assert actual.read_bytes() == new_map, "production mapping rerun differs"

    old_log = original("evidence/access.log.gz")
    old_lines = gzip.decompress(old_log).splitlines(keepends=True)
    new_lines = []
    rewritten = 0
    for line in old_lines:
        client, rest = line.split(b" ", 1)
        new_client = changes.get(client, client)
        rewritten += new_client != client
        new_lines.append(new_client + b" " + rest)
    new_log = gzip.compress(b"".join(new_lines), mtime=0)
    expected = {"evidence/access.log.gz": new_log, "replay/ip_map.tsv": new_map}

    old_sidecar = gzip.decompress(original("replay/labels.log.gz"))
    new_sidecar = []
    for line in old_sidecar.splitlines(keepends=True):
        item = json.loads(line)
        old = item["client_ip"].encode()
        if old in changes:
            line, count = re.subn(
                rb'("client_ip"\s*:\s*")' + re.escape(old) + rb'(")',
                lambda m, replacement=changes[old]: m[1] + replacement + m[2], line,
            )
            assert count == 1
        after = json.loads(line)
        assert {k: v for k, v in item.items() if k != "client_ip"} == {
            k: v for k, v in after.items() if k != "client_ip"
        }
        new_sidecar.append(line)
    expected["replay/labels.log.gz"] = gzip.compress(b"".join(new_sidecar), mtime=0)
    if apply:
        for relative, data in expected.items():
            path = scenario / relative
            assert path.read_bytes() in (original(relative), data), "unexpected evidence edits"
            path.write_bytes(data)
    else:
        for relative, data in expected.items():
            assert (scenario / relative).read_bytes() == data

    truth_bytes = (scenario / "ground_truth.json").read_bytes()
    truth = json.loads(truth_bytes)
    records = json.loads((replay / "records.json").read_bytes())
    generated = label.make_ground_truth(
        records, scenario / "evidence", replay / "labels.log.gz", scenario_id
    )
    assert encoded(generated) == truth_bytes
    assert generated["attacker_ips"] == json.loads(original("ground_truth.json"))["attacker_ips"]
    access = label.access_index(scenario / "evidence/access.log.gz")
    actors = self_check.activity_ips(truth, access)
    actor_count = 0
    for before, after in zip(old_lines, new_lines, strict=True):
        old_client, old_rest = before.split(b" ", 1)
        new_client, new_rest = after.split(b" ", 1)
        assert old_rest == new_rest  # timestamp/request/status/size/referrer/UA, byte for byte
        assert new_client == changes.get(old_client, old_client)
        if old_client.decode() in actors:
            assert before == after
            actor_count += 1
    for step in truth["steps"]:
        n = step["line_no"] - 1
        assert old_lines[n] == new_lines[n]
    old_counts = Counter(line.split(b" ", 1)[0].decode() for line in old_lines)
    new_counts = Counter(row["client_ip"] for row in access)
    assert sorted(old_counts.values()) == sorted(new_counts.values())
    assert self_check.private_client_count(new_counts) == 0

    review = json.loads(original("replay/analyst-review.json"))
    assert review["access_log_sha256"] == sha(old_log)
    review["access_log_sha256"] = sha(new_log)
    review["round8_rebind"] = {
        "historical_access_log_sha256": sha(old_log),
        "reason": "Approved background address remap only; all other fields byte-identical",
        "field_comparison": "PASS", "actor_lines_byte_identical": actor_count,
    }
    if apply:
        (replay / "analyst-review.json").write_bytes(encoded(review))
    else:
        assert (replay / "analyst-review.json").read_bytes() == encoded(review)

    proof = {
        "scenario": scenario_id, "original_revision": revision, "seed": seed,
        "rule": ("Production IPMapper in recorded first-seen order; "
                 "replace only old overflow clients"),
        "historical_overflow_range": "10.0.0.0/8", "new_overflow_range": "198.18.0.0/15",
        "documentation_ranges_first": [str(n) for n in background.BACKGROUND_POOLS[:3]],
        "addresses_rewritten": len(changes), "rows_rewritten": rewritten,
        "private_client_addresses_before": self_check.private_client_count(old_counts),
        "private_client_addresses_after": self_check.private_client_count(new_counts),
        "historical_log_sha256_before": sha(old_log), "log_sha256_after": sha(new_log),
        "client_count_before": len(old_counts), "client_count_after": len(new_counts),
        "background_client_count": len(mapper.mapping),
        "top_client_share_before": max(old_counts.values()) / len(old_lines),
        "top_client_share_after": max(new_counts.values()) / len(new_lines),
        "rows_before": len(old_lines), "rows_after": len(new_lines),
        "all_non_client_fields_byte_identical": True,
        "all_actor_lines_byte_identical": actor_count,
        "ground_truth_step_lines_byte_identical": len(truth["steps"]),
        "ground_truth_regeneration": "PASS; byte-identical; attacker_ips unchanged",
        "mapping_rerun": ("PASS; production IPMapper over recorded background.log.gz, "
                          "byte-identical TSV"),
        "ip_map_sha256": sha(new_map),
        "encrypted_capture": "Unchanged; holds the original mapping",
        "restore": "Prior proof retained; webroot, manifests and restore inputs unchanged",
        "leftover_old_range_literals": [],
    }
    proof_path = replay / "ip-remap.json"
    if apply:
        proof_path.write_bytes(encoded(proof))
    proof["leftover_old_range_literals"] = leftovers(scenario)
    if apply:
        proof_path.write_bytes(encoded(proof))
    else:
        assert json.loads(proof_path.read_bytes()) == proof
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-revision", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    for n in range(1, 13):
        proof = remap(Path.cwd(), f"s{n:02}", args.original_revision, args.apply)
        print(proof["scenario"], proof["addresses_rewritten"], proof["rows_rewritten"], "PASS")


if __name__ == "__main__":
    main()
