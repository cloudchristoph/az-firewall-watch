"""Customer-controlled maintenance windows: fetch, cache round trip, and the
Firewall-tab rendering (0.6.0 point 5)."""
from __future__ import annotations

from pathlib import Path

import pytest

import viewer.cache as cache
from viewer.arm import ArmError
from viewer.azure_resources import FirewallInfo, MaintenanceWindow, fetch_maintenance
from viewer.views.firewall import _maintenance_rows, _note, _row

SUB = "/subscriptions/25ca1d83-3de5-46c7-9941-fb98c2ea026e"
FW_ID = f"{SUB}/resourceGroups/rg-hub-network-gwc/providers/Microsoft.Network/azureFirewalls/fw-hub-gwc"
ASSIGNMENTS_PATH = f"{FW_ID}/providers/Microsoft.Maintenance/configurationAssignments"
MAINT_RG = f"{SUB}/resourceGroups/rg-maintenance"
CONFIG_ID = f"{MAINT_RG}/providers/Microsoft.Maintenance/maintenanceConfigurations/mc-fw-nightly"


class FakeArm:
    """Stand-in for ArmClient: answers GETs from a path → payload map."""

    def __init__(self, routes: dict) -> None:
        self.routes = routes
        self.calls: list[str] = []

    async def get(self, path: str, api_version: str, *, params=None) -> dict:
        self.calls.append(path)
        if path not in self.routes:
            raise ArmError(404, "ResourceNotFound", f"no route for {path}")
        payload = self.routes[path]
        if isinstance(payload, Exception):
            raise payload
        return payload

    async def get_all(self, path: str, api_version: str, *, params=None) -> list:
        self.calls.append(path)
        payload = self.routes.get(path, {"value": []})
        if isinstance(payload, Exception):
            raise payload
        return list(payload.get("value", []))


def _fw() -> FirewallInfo:
    return FirewallInfo(id=FW_ID, name="fw-hub-gwc", subscription_id="s", resource_group="rg-hub-network-gwc",
                        location="germanywestcentral")


CONFIG_JSON_FULL = {
    "name": "mc-fw-nightly",
    "properties": {
        "maintenanceScope": "Resource",
        "extensionProperties": {"maintenanceSubScope": "NetworkSecurity"},
        "maintenanceWindow": {
            "startDateTime": "2020-01-01 22:00",
            "expirationDateTime": "9999-12-31 23:59",
            "duration": "05:00",
            "timeZone": "W. Europe Standard Time",
            "recurEvery": "Day",
        },
    },
}


# ── fetch_maintenance ───────────────────────────────────────────────────────

async def test_fetch_maintenance_reads_assignment_and_readable_configuration():
    arm = FakeArm({
        ASSIGNMENTS_PATH: {"value": [
            {"name": "assign1", "properties": {"maintenanceConfigurationId": CONFIG_ID, "resourceId": FW_ID}},
        ]},
        CONFIG_ID: CONFIG_JSON_FULL,
    })
    windows = await fetch_maintenance(arm, FW_ID)
    assert len(windows) == 1
    w = windows[0]
    assert w.assignment_name == "assign1"
    assert w.configuration_id == CONFIG_ID
    assert w.configuration_name == "mc-fw-nightly"
    assert w.readable is True
    assert w.scope == "Resource"
    assert w.sub_scope == "NetworkSecurity"
    assert w.start == "2020-01-01 22:00"
    assert w.duration == "05:00"
    assert w.time_zone == "W. Europe Standard Time"
    assert w.recur_every == "Day"
    assert w.expiration == "9999-12-31 23:59"


async def test_fetch_maintenance_configuration_missing_keys_defaults_to_empty_strings():
    arm = FakeArm({
        ASSIGNMENTS_PATH: {"value": [
            {"name": "assign1", "properties": {"maintenanceConfigurationId": CONFIG_ID}},
        ]},
        CONFIG_ID: {"name": "mc-fw-nightly", "properties": {}},
    })
    windows = await fetch_maintenance(arm, FW_ID)
    w = windows[0]
    assert w.readable is True
    assert w.configuration_name == "mc-fw-nightly"
    assert (w.scope, w.sub_scope, w.start, w.duration, w.time_zone, w.recur_every, w.expiration) == ("",) * 7


async def test_fetch_maintenance_configuration_get_raises_arm_error_marks_unreadable():
    arm = FakeArm({
        ASSIGNMENTS_PATH: {"value": [
            {"name": "assign1", "properties": {"maintenanceConfigurationId": CONFIG_ID}},
        ]},
        CONFIG_ID: ArmError(403, "AuthorizationFailed", "no Reader on the maintenance configuration"),
    })
    windows = await fetch_maintenance(arm, FW_ID)
    w = windows[0]
    assert w.readable is False
    assert w.configuration_name == "mc-fw-nightly"          # last path segment of the id
    assert w.assignment_name == "assign1"
    assert w.start == "" and w.scope == ""                  # nothing else guessed at


@pytest.mark.parametrize("status,code", [(404, "ResourceNotFound"), (409, "MissingSubscriptionRegistration")])
async def test_fetch_maintenance_assignment_list_arm_error_returns_empty(status, code):
    arm = FakeArm({ASSIGNMENTS_PATH: ArmError(status, code, "boom")})
    assert await fetch_maintenance(arm, FW_ID) == []


async def test_fetch_maintenance_empty_list():
    arm = FakeArm({ASSIGNMENTS_PATH: {"value": []}})
    assert await fetch_maintenance(arm, FW_ID) == []


async def test_fetch_maintenance_assignment_without_configuration_id():
    """An assignment whose properties carry no maintenanceConfigurationId: no GET is attempted."""
    arm = FakeArm({ASSIGNMENTS_PATH: {"value": [{"name": "assign1", "properties": {}}]}})
    windows = await fetch_maintenance(arm, FW_ID)
    assert len(windows) == 1
    assert windows[0].configuration_id == "" and windows[0].readable is False
    assert CONFIG_ID not in arm.calls


# ── cache round trip ─────────────────────────────────────────────────────────

@pytest.fixture
def cache_file(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "cache.json"
    monkeypatch.setattr(cache, "cache_path", lambda: path)
    return path


def test_maintenance_round_trips_through_the_cache(cache_file):
    from viewer.azure_resources import FirewallPolicyInfo

    fw = _fw()
    fw.policy_id = "/p"
    policy = FirewallPolicyInfo(id="/p", name="pol")
    maintenance = [
        MaintenanceWindow(assignment_name="assign1", configuration_id=CONFIG_ID, configuration_name="mc-fw-nightly",
                          readable=True, start="2020-01-01 22:00", duration="05:00",
                          time_zone="W. Europe Standard Time", recur_every="Day",
                          expiration="9999-12-31 23:59", scope="Resource", sub_scope="NetworkSecurity"),
        MaintenanceWindow(assignment_name="assign2", configuration_id=f"{MAINT_RG}/mc2", readable=False),
    ]
    snap = cache.CachedSnapshot(firewall=fw, policy=policy, maintenance=maintenance, fetched_at=1.0)
    cache.save(FW_ID, snap)
    loaded = cache.load(FW_ID)
    assert loaded is not None
    assert loaded.maintenance == maintenance


def test_maintenance_defaults_to_empty_list_when_absent_from_an_older_cache_entry(cache_file):
    import json

    entry = {"firewall": {"id": FW_ID, "name": "fw", "subscription_id": "s", "resource_group": "rg", "location": "gwc"},
             "policy": None, "fetched_at": 1.0}
    cache_file.write_text(json.dumps({"_version": cache._CACHE_VERSION, "entries": {FW_ID: entry}}))
    loaded = cache.load(FW_ID)
    assert loaded is not None and loaded.maintenance == []


# ── Firewall-tab rendering ───────────────────────────────────────────────────

def test_maintenance_rows_empty_list():
    assert _maintenance_rows(_fw(), []) == [
        _row("Maintenance", "no customer-controlled window   [dim]Azure picks the time for updates[/]"),
    ]


def test_maintenance_rows_readable_window_common_case():
    # Start far in the past and the "9999-…" sentinel expiration: no "from …" prefix, no "until …" suffix.
    w = MaintenanceWindow(assignment_name="assign1", configuration_id=CONFIG_ID, configuration_name="mc-fw-nightly",
                          readable=True, start="2020-01-01 22:00", duration="05:00",
                          time_zone="W. Europe Standard Time", recur_every="Day",
                          expiration="9999-12-31 23:59", scope="Resource", sub_scope="NetworkSecurity")
    rows = _maintenance_rows(_fw(), [w])
    assert rows == [
        _row("Maintenance", "daily 22:00 for 5 h, W. Europe Standard Time   [dim]mc-fw-nightly[/]"),
        _note("covers guest OS and service updates; host updates and urgent security fixes can fall outside the window"),
    ]


@pytest.mark.parametrize("missing,expect_missing,expect_present", [
    ({"start": ""}, "start", "duration 05:00 · zone W. Europe Standard Time · recurs Day"),
    ({"duration": "", "time_zone": ""}, "duration, time zone", "start 2020-01-01 22:00 · recurs Day"),
    ({"start": "", "duration": "", "time_zone": "", "recur_every": ""}, "start, duration, time zone", ""),
])
def test_maintenance_rows_with_missing_fields_say_so_instead_of_a_sentence_with_blanks(missing, expect_missing, expect_present):
    w = MaintenanceWindow(assignment_name="assign1", configuration_id=CONFIG_ID, configuration_name="mc-fw-nightly",
                          readable=True, start="2020-01-01 22:00", duration="05:00",
                          time_zone="W. Europe Standard Time", recur_every="Day", **{})
    for k, v in missing.items():
        setattr(w, k, v)
    rows = _maintenance_rows(_fw(), [w])
    assert len(rows) == 1
    assert f"[yellow]assigned, but the configuration names no {expect_missing}[/]" in rows[0]
    assert "mc-fw-nightly" in rows[0]
    if expect_present:
        assert expect_present in rows[0]
    assert " for , " not in rows[0] and "daily  " not in rows[0]


def test_maintenance_rows_duration_with_minutes():
    w = MaintenanceWindow(assignment_name="a", configuration_name="mc", readable=True,
                          start="2020-01-01 22:00", duration="05:30", time_zone="UTC", recur_every="Day",
                          expiration="9999-12-31 23:59")
    rows = _maintenance_rows(_fw(), [w])
    assert rows[0] == _row("Maintenance", "daily 22:00 for 5 h 30 min, UTC   [dim]mc[/]")


def test_maintenance_rows_unparseable_duration_shown_raw():
    w = MaintenanceWindow(assignment_name="a", configuration_name="mc", readable=True,
                          start="2020-01-01 22:00", duration="bogus", time_zone="UTC", recur_every="Day",
                          expiration="9999-12-31 23:59")
    rows = _maintenance_rows(_fw(), [w])
    assert rows[0] == _row("Maintenance", "daily 22:00 for bogus, UTC   [dim]mc[/]")


def test_maintenance_rows_non_daily_recurrence():
    w = MaintenanceWindow(assignment_name="a", configuration_name="mc", readable=True,
                          start="2020-01-01 22:00", duration="05:00", time_zone="UTC", recur_every="3Days",
                          expiration="9999-12-31 23:59")
    rows = _maintenance_rows(_fw(), [w])
    assert rows[0] == _row("Maintenance", "every 3Days 22:00 for 5 h, UTC   [dim]mc[/]")


def test_maintenance_rows_future_start_gets_from_prefix():
    w = MaintenanceWindow(assignment_name="a", configuration_name="mc", readable=True,
                          start="2099-06-15 22:00", duration="05:00", time_zone="UTC", recur_every="Day",
                          expiration="9999-12-31 23:59")
    rows = _maintenance_rows(_fw(), [w])
    assert rows[0] == _row("Maintenance", "from 2099-06-15, daily 22:00 for 5 h, UTC   [dim]mc[/]")


def test_maintenance_rows_expiration_set_in_the_future_is_appended():
    w = MaintenanceWindow(assignment_name="a", configuration_name="mc", readable=True,
                          start="2020-01-01 22:00", duration="05:00", time_zone="UTC", recur_every="Day",
                          expiration="2099-12-31 23:59")
    rows = _maintenance_rows(_fw(), [w])
    assert rows[0] == _row("Maintenance", "daily 22:00 for 5 h, UTC until 2099-12-31   [dim]mc[/]")


def test_maintenance_rows_expired_window_skips_the_note():
    w = MaintenanceWindow(assignment_name="a", configuration_name="mc-fw-nightly", readable=True,
                          start="2010-01-01 22:00", duration="05:00", time_zone="UTC", recur_every="Day",
                          expiration="2020-06-30 23:59")
    rows = _maintenance_rows(_fw(), [w])
    assert rows == [_row("Maintenance", "[yellow]expired 2020-06-30[/]   [dim]mc-fw-nightly[/]")]


def test_maintenance_rows_unexpected_sub_scope_is_flagged():
    w = MaintenanceWindow(assignment_name="a", configuration_name="mc", readable=True,
                          start="2020-01-01 22:00", duration="05:00", time_zone="UTC", recur_every="Day",
                          expiration="9999-12-31 23:59", sub_scope="Foo")
    rows = _maintenance_rows(_fw(), [w])
    assert rows[0] == _row("Maintenance",
                           "daily 22:00 for 5 h, UTC   [yellow]subscope Foo: not a firewall maintenance window[/]"
                           "   [dim]mc[/]")


def test_maintenance_rows_not_readable():
    w = MaintenanceWindow(assignment_name="assign1", configuration_id=CONFIG_ID, configuration_name="mc-fw-nightly",
                          readable=False)
    rows = _maintenance_rows(_fw(), [w])
    assert rows == [
        _row("Maintenance", "assigned: mc-fw-nightly   [dim]window not readable "
             "(no Reader on the maintenance configuration)[/]"),
    ]


def test_maintenance_rows_several_entries_each_get_their_own_row_and_note_in_order():
    readable = MaintenanceWindow(assignment_name="a1", configuration_name="mc-a", readable=True,
                                 start="2020-01-01 22:00", duration="05:00", time_zone="UTC", recur_every="Day",
                                 expiration="9999-12-31 23:59")
    unreadable = MaintenanceWindow(assignment_name="a2", configuration_id=CONFIG_ID, configuration_name="mc-b",
                                   readable=False)
    rows = _maintenance_rows(_fw(), [readable, unreadable])
    assert rows == [
        _row("Maintenance", "daily 22:00 for 5 h, UTC   [dim]mc-a[/]"),
        _note("covers guest OS and service updates; host updates and urgent security fixes can fall outside the window"),
        _row("Maintenance", "assigned: mc-b   [dim]window not readable (no Reader on the maintenance configuration)[/]"),
    ]


def test_maintenance_rows_names_are_escaped():
    from rich.markup import escape as _esc

    w = MaintenanceWindow(assignment_name="a[bold]", configuration_name="mc[/bold]", readable=False)
    rows = _maintenance_rows(_fw(), [w])
    # escape() backslash-escapes brackets so the raw name can never inject markup
    assert _esc("mc[/bold]") in rows[0]
    assert "mc[/bold]" not in rows[0]
