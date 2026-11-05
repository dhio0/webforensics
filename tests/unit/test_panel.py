"""Sites created through a hosting panel by an address never seen before (D98)."""

from datetime import timedelta

from tests.correlate_helpers import request
from webforensics.correlate import correlate
from webforensics.correlate.panel import PANEL_RULE, is_site_management, panel_leads
from webforensics.models import FileCollection, LogCollection

DAY = 86_400
ADMIN = "198.51.100.5"
NEWCOMER = "203.0.113.99"


def logs(*specs):
    return LogCollection(events=tuple(
        request(n, seconds, target, **kw) for n, (seconds, target, kw) in enumerate(specs, 1)))


def test_site_creation_endpoints_of_each_panel():
    def managed(target, method="POST", status=200):
        return is_site_management(request(1, 0, target, method=method, status=status))

    assert managed("/websites/submitWebsiteCreation")  # CyberPanel web UI
    assert managed("/dns/zoneCreation")
    assert managed("/api/createWebsite")  # CyberPanel API
    assert managed("/cpsess123/execute/SubDomain/addsubdomain?domain=x", method="GET")
    assert managed("/execute/AddonDomain/addaddondomain", method="GET")  # cPanel UAPI
    assert managed("/json-api/createacct?api.version=1&domain=x", method="GET")  # WHM
    assert managed("/CMD_API_DOMAIN")  # DirectAdmin
    assert managed("/site?action=AddSite", method="GET")  # aaPanel


def test_viewing_forms_failures_and_other_pages_are_not():
    def managed(target, method="POST", status=200):
        return is_site_management(request(1, 0, target, method=method, status=status))

    assert not managed("/websites/submitWebsiteCreation", method="GET")  # the form itself
    assert not managed("/websites/submitWebsiteCreation", status=403)
    assert not managed("/websites/submitWebsiteCreation", status=302)
    assert not managed("/websites/listWebsites")
    assert not managed("/site?action=GetSites", method="GET")
    assert not managed("/site?action=AddSiteX", method="GET")
    assert not managed("/blog/site?action=AddSite", method="GET")  # aaPanel's is at the root


def _case(first_newcomer_day: float, log_start_day: float = 0):
    return logs(
        (log_start_day * DAY, "/", {"ip": ADMIN}),
        (first_newcomer_day * DAY, "/verifyLogin", {"ip": NEWCOMER, "method": "POST"}),
        (first_newcomer_day * DAY + 60, "/websites/submitWebsiteCreation",
         {"ip": NEWCOMER, "method": "POST"}),
        (first_newcomer_day * DAY + 90, "/dns/zoneCreation", {"ip": NEWCOMER, "method": "POST"}),
        (first_newcomer_day * DAY + 120, "/websites/submitWebsiteCreation",
         {"ip": ADMIN, "method": "POST"}),
    )


def test_a_new_address_creating_sites_is_a_lead_and_not_an_accusation():
    result = correlate(_case(8), FileCollection(files=()))
    leads = [f for f in result.findings if f.rule_id == PANEL_RULE]
    assert len(leads) == 1  # the newcomer; the admin was seen on day 0
    params = leads[0].reasons[0].params
    assert params["count"] == "2" and params["days"] == "8"
    assert params["paths"] == "/dns/zoneCreation, /websites/submitWebsiteCreation"
    assert leads[0].confidence.value == "low"
    assert NEWCOMER not in result.iocs.ips
    assert result.affected_files == () and result.root_cause is None


def test_too_little_log_history_says_nothing():
    """With three days of log every address looks new."""
    result = correlate(_case(3), FileCollection(files=()))
    assert not [f for f in result.findings if f.rule_id == PANEL_RULE]


def test_addresses_of_the_incident_are_left_out():
    events = _case(8).events
    found = panel_leads(events, lambda e: e.client_ip, (events[0].ts, events[-1].ts),
                        timedelta(days=7), {NEWCOMER})
    assert found == []
