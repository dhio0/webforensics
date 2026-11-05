"""Advice that must not hurt the site: restore needed files instead of deleting them, and
name the files whose code was not read."""

from tests.correlate_helpers import file_ev
from webforensics.models import BaselineStatus, CodeScope
from webforensics.report.build import code_limitations, needs_restore


def status(path, value):
    return file_ev(path).model_copy(update={"baseline_status": value})


def test_entry_points_and_modified_files_are_restored_not_deleted():
    assert needs_restore(status("index.php", BaselineStatus.UNKNOWN))
    assert needs_restore(status("shop/.htaccess", BaselineStatus.UNKNOWN))
    assert needs_restore(status("lib/db.php", BaselineStatus.MODIFIED))


def test_new_files_are_deleted():
    assert not needs_restore(status("uploads/shell.php", BaselineStatus.UNKNOWN))
    assert not needs_restore(status("uploads/shell.php", BaselineStatus.NEW))
    # An index page the baseline never had is the attacker's: delete it.
    assert not needs_restore(status("slot-gacor/index.html", BaselineStatus.NEW))


def test_the_code_limitation_names_the_missing_files():
    (reason,) = code_limitations(CodeScope(no_content=("wp-admin/admin-ajax.php",)))
    assert reason.key == "limit.no_code_content"
    assert reason.params["paths"] == "wp-admin/admin-ajax.php"
    (reason,) = code_limitations(CodeScope(analyzed=("a.php",)))
    assert reason.key == "limit.code_scope"
    assert code_limitations(None) == ()
