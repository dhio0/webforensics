"""Edge cases of the correlation engine on small synthetic evidence."""

from tests.correlate_helpers import (
    ATTACKER,
    VISITOR,
    file_ev,
    files,
    line_of,
    numbered,
    root_event,
)
from webforensics.correlate import CorrelationConfig, correlate
from webforensics.models import BaselineStatus, Confidence, FileCollection, TimestampBasis

SHELL = "uploads/x.php"


def _keys(result):
    return [e.description.key for e in result.timeline]


def test_sqli_login_by_other_ip_is_not_blamed():
    logs = numbered(
        (0, "/admin/login.php?u=a%27+OR+%271%27%3D%271+--+", {"ip": VISITOR}),
        (10, "/admin/upload.php", {"method": "POST"}),
        (12, "/uploads/x.php"),
    )
    result = correlate(logs, files(file_ev(SHELL, btime=10, ctime=10, mtime=10)))
    root = root_event(result)
    assert line_of(result, root) == 2
    assert root.actor == ATTACKER
    assert VISITOR not in result.iocs.ips
    assert all(e.actor != VISITOR for e in result.timeline)


def test_sqli_on_unrelated_area_is_context_only():
    logs = numbered(
        (0, "/shop/item.php?id=1+UNION+SELECT+1,2"),
        (5, "/admin/login.php", {"method": "POST", "status": 302}),
        (10, "/admin/upload.php", {"method": "POST"}),
    )
    result = correlate(logs, files(file_ev(SHELL, btime=10, ctime=10, mtime=10)))
    root = root_event(result)
    # A login whose method we cannot see becomes a low-confidence entry point.
    assert root.description.key == "timeline.login_method_unknown"
    assert result.root_cause.confidence is Confidence.LOW
    assert result.root_cause.vuln_class is None
    assert "timeline.exploit_attempt" in _keys(result)


def test_file_without_any_http_write_is_reported_not_invented():
    logs = numbered((0, "/"), (5, "/about.php"), (30, "/uploads/x.php"))
    result = correlate(logs, files(file_ev(SHELL, btime=8, ctime=8, mtime=8)))
    assert result.root_cause is None
    created = next(e for e in result.timeline if e.description.key == "timeline.file_created")
    assert "creation.no_http_request_found" in [r.key for r in created.confidence_reasons]
    assert "timeline.file_invoked" in _keys(result)


def test_mtime_only_caps_confidence_at_medium():
    logs = numbered((10, "/upload.php", {"method": "POST"}), (12, "/uploads/x.php"))
    result = correlate(logs, files(file_ev(SHELL, mtime=10)))
    file_event = next(e for e in result.timeline if e.ts_basis is TimestampBasis.MTIME)
    assert file_event.confidence is Confidence.MEDIUM
    assert root_event(result).confidence is Confidence.MEDIUM


def test_two_equal_uploads_are_kept_as_alternatives():
    logs = numbered(
        (8, "/upload.php", {"method": "POST"}),
        (10, "/upload.php", {"method": "POST"}),
        (12, "/uploads/x.php"),
    )
    result = correlate(logs, files(file_ev(SHELL, btime=10, ctime=10, mtime=10)))
    assert line_of(result, root_event(result)) == 2  # closest to the anchor
    assert len(result.root_cause.alternative_event_ids) == 1
    alt = next(e for e in result.timeline
               if e.event_id == result.root_cause.alternative_event_ids[0])
    assert line_of(result, alt) == 1
    assert root_event(result).confidence is Confidence.MEDIUM


def test_timestomped_file_anchors_on_birth_and_is_flagged():
    logs = numbered((100, "/upload.php", {"method": "POST"}), (102, "/uploads/x.php"))
    stomped = file_ev(SHELL, btime=100, ctime=400, mtime=-86400)
    result = correlate(logs, files(stomped))
    assert line_of(result, root_event(result)) == 1
    stomp = next(e for e in result.timeline if e.description.key == "timeline.file_timestomp")
    assert stomp.mitre_technique == "T1070.006"
    assert any(f.rule_id == "FILE-ANTIFORENSICS-TIMESTOMP" for f in result.findings)


def test_baseline_unchanged_file_is_not_a_seed_and_new_file_is():
    logs = numbered((10, "/upload.php", {"method": "POST"}))
    current = files(
        file_ev(SHELL, btime=10, ctime=10, mtime=10),
        file_ev("lib/new.php", btime=10, ctime=10, mtime=10, content="new"),
    )
    baseline = FileCollection(files=(current.files[0],))
    result = correlate(logs, current, baseline=baseline)
    assert [f.path for f in result.affected_files] == ["lib/new.php"]
    assert result.affected_files[0].baseline_status is BaselineStatus.NEW
    assert all(g.kind.value != "no_baseline" for g in result.gaps)


def test_no_suspicious_files_means_no_root_cause_and_findings_unattributed():
    logs = numbered((0, "/item.php?id=1+UNION+SELECT+1"))
    result = correlate(logs, files(file_ev("index.php", btime=0, ctime=0, mtime=0)))
    assert result.root_cause is None
    assert result.timeline == ()
    assert len(result.unattributed_finding_ids) == 1


def test_file_outside_log_coverage_gets_coverage_gap():
    logs = numbered((0, "/"), (5, "/a"))
    result = correlate(logs, files(file_ev(SHELL, btime=7200, ctime=7200, mtime=7200)),
                       config=CorrelationConfig())
    gap = next(g for g in result.gaps if g.detail and g.detail.key == "gap.no_log_coverage")
    created = next(e for e in result.timeline if e.description.key == "timeline.file_created")
    assert created.event_id in gap.affects
    assert created.confidence is Confidence.MEDIUM


def test_put_to_file_url_is_the_write_not_an_invocation():
    logs = numbered((10, "/uploads/x.php", {"method": "PUT", "status": 201}),
                    (12, "/uploads/x.php"))
    result = correlate(logs, files(file_ev(SHELL, btime=10, ctime=10, mtime=10)))
    lines = [line_of(result, e) for e in result.timeline if e.citations[0].line_no]
    assert lines == [1, 2]
    assert root_event(result).description.key == "timeline.upload_exploit"


def test_two_files_from_one_bypass_share_one_root():
    logs = numbered(
        (0, "/admin/login.php?u=a%27+OR+%271%27%3D%271+--+"),
        (10, "/admin/upload.php", {"method": "POST"}),
        (20, "/admin/upload.php", {"method": "POST"}),
    )
    result = correlate(logs, files(file_ev("uploads/a.php", btime=10, ctime=10, mtime=10),
                                   file_ev("uploads/b.php", btime=20, ctime=20, mtime=20)))
    assert sum(e.is_root_cause for e in result.timeline) == 1
    assert line_of(result, root_event(result)) == 1
    assert result.root_cause.alternative_event_ids == ()


ADMIN = "198.51.100.50"


def _upload_then_comment(*extra):
    logs = numbered(
        (10, "/admin/auth_upload.php", {"method": "POST", "ip": ADMIN}),
        (12, "/comment.php", {"method": "POST", "ip": VISITOR}),
    )
    cache = file_ev("cache/page-1.php", btime=12, ctime=12, mtime=12)
    return correlate(logs, files(cache, *extra))


def test_upload_explained_by_its_own_file_does_not_claim_a_nearby_cache_file():
    # D69: both requests are within clock skew of the cache file's birth, but the photo
    # was born at the upload's own second, so the upload wrote the photo.
    photo = file_ev("uploads/photo.png", btime=10, ctime=10, mtime=10)
    result = _upload_then_comment(photo)
    assert result.root_cause is None and result.iocs.ips == ()
    assert result.unexplained_changes == ("cache/page-1.php",)


def test_without_the_uploads_own_file_the_upload_still_ranks_first():
    # Ranking only: if the photo is missing from the evidence, nothing explains the
    # upload, so it keeps winning (and is reported, with the comment as context).
    result = _upload_then_comment()
    assert line_of(result, root_event(result)) == 1


def test_one_request_writing_two_files_in_the_same_second_is_not_demoted():
    logs = numbered((10, "/admin/upload.php", {"method": "POST"}), (11, "/uploads/x.php"),
                    (11, "/comment.php", {"method": "POST", "ip": VISITOR}))
    shell = file_ev(SHELL, btime=10, ctime=10, mtime=10)
    thumb = file_ev("uploads/thumb.png", btime=10, ctime=10, mtime=10)
    result = correlate(logs, files(shell, thumb))
    assert line_of(result, root_event(result)) == 1


def test_an_incident_actors_extra_bypass_is_not_reported_as_unrelated():
    # D71: the "unrelated bypass" finding is for clients outside the incident only.
    from webforensics.correlate.engine import _Index, _unlinked_bypasses

    logs = numbered((0, "/admin/login.php?u=a%27+OR+%271%27%3D%271+--+", {"size": 347}))
    index = _Index(logs, CorrelationConfig())
    assert len(_unlinked_bypasses(index, set(), set())) == 1
    assert _unlinked_bypasses(index, set(), {ATTACKER}) == []
