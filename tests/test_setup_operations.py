"""setup/operations.py against a scriptable fake Azure CLI."""
from __future__ import annotations

import json
import subprocess
from typing import Any, Callable

import pytest

import setup.operations as ops

FW = {
    "name": "fw-hub", "rg": "rg-hub", "location": "germanywestcentral",
    "id": "/subscriptions/s1/resourceGroups/rg-hub/providers/Microsoft.Network/azureFirewalls/fw-hub",
}


class FakeAz:
    """Records every ``az`` invocation and answers from a list of rules.

    A rule is ``(prefix, result)`` where *prefix* is a tuple of leading CLI
    args and *result* is ``stdout`` (str / JSON-able) or ``(returncode, stdout)``.
    The first matching rule wins; unmatched calls succeed with empty output.
    """

    def __init__(self) -> None:
        self.rules: list[tuple[tuple[str, ...], Any]] = []
        self.calls: list[tuple[str, ...]] = []

    def on(self, *prefix: str, result: Any = "", rc: int = 0) -> "FakeAz":
        self.rules.append((prefix, (rc, result)))
        return self

    async def __call__(self, *args: str, capture: bool = True, check: bool = False):
        self.calls.append(args)
        rc, out = 0, ""
        for prefix, (r, o) in self.rules:
            if args[: len(prefix)] == prefix:
                rc, out = r, o
                break
        stdout = out if isinstance(out, str) else json.dumps(out)
        if check and rc != 0:
            raise subprocess.CalledProcessError(rc, ["az", *args], output=stdout, stderr="fail")
        return subprocess.CompletedProcess(["az", *args], rc, stdout=stdout, stderr="")

    def called(self, *prefix: str) -> list[tuple[str, ...]]:
        return [c for c in self.calls if c[: len(prefix)] == prefix]


@pytest.fixture
def az(monkeypatch) -> FakeAz:
    fake = FakeAz()
    monkeypatch.setattr(ops, "az_async", fake)
    monkeypatch.setattr(ops, "find_az", lambda: "/usr/bin/az")
    return fake


@pytest.fixture
def log() -> list[str]:
    return []


def _logger(lines: list[str]) -> Callable[[Any], None]:
    return lambda msg: lines.append(str(msg))


# ── login ────────────────────────────────────────────────────────────────────

async def test_ensure_login_when_already_logged_in(az, log):
    az.on("version", result="2.70.0\n")
    az.on("account", "show", result="me@example.com\n")
    az.on("ad", "signed-in-user", "show", result="oid-123\n")
    suspend_calls: list[bool] = []

    class _Suspend:
        def __enter__(self): suspend_calls.append(True)
        def __exit__(self, *a): return False

    user, oid = await ops.cli_ensure_login(_logger(log), lambda: _Suspend())
    assert (user, oid) == ("me@example.com", "oid-123")
    assert suspend_calls == []
    assert any("2.70.0" in line for line in log)


async def test_ensure_login_runs_az_login_when_needed(az, log, monkeypatch):
    az.on("version", result="2.70.0\n")
    state = {"logged_in": False}

    async def _acc(*args, capture=True, check=False):
        az.calls.append(args)
        if args[:2] == ("account", "show"):
            if state["logged_in"]:
                return subprocess.CompletedProcess(args, 0, stdout="me@example.com\n", stderr="")
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="Please run 'az login'")
        return await FakeAz.__call__(az, *args, capture=capture, check=check)

    monkeypatch.setattr(ops, "az_async", _acc)
    login_cmds: list[list[str]] = []

    def _run(cmd, check=False):
        login_cmds.append(cmd)
        state["logged_in"] = True
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(ops.subprocess, "run", _run)
    suspended: list[bool] = []

    class _Suspend:
        def __enter__(self): suspended.append(True)
        def __exit__(self, *a): return False

    user, oid = await ops.cli_ensure_login(_logger(log), lambda: _Suspend())
    assert user == "me@example.com"
    assert oid == ""  # signed-in-user lookup answered with empty output
    assert login_cmds == [["/usr/bin/az", "login"]]
    assert suspended == [True]


async def test_ensure_login_without_cli_raises(monkeypatch, log):
    monkeypatch.setattr(ops, "find_az", lambda: None)
    with pytest.raises(RuntimeError, match="Azure CLI not found"):
        await ops.cli_ensure_login(_logger(log), lambda: None)


# ── discovery ────────────────────────────────────────────────────────────────

async def test_list_subscriptions(az, log):
    az.on("account", "list", result=[{"id": "s1", "name": "Sub One"}, {"id": "s2", "name": "Sub Two"}])
    subs = await ops.list_subscriptions(_logger(log))
    assert [s["id"] for s in subs] == ["s1", "s2"]
    assert any("Found 2 subscription" in line for line in log)


async def test_list_subscriptions_on_error_is_empty(az, log):
    az.on("account", "list", rc=1)
    assert await ops.list_subscriptions(_logger(log)) == []


async def test_scan_event_hubs_across_subscriptions(az, log):
    az.on("eventhubs", "namespace", "list", "--subscription", "s1", result=[{"name": "ns-a", "rg": "rg-a"}])
    az.on("eventhubs", "namespace", "list", "--subscription", "s2", rc=1)  # no access → skipped
    az.on("eventhubs", "eventhub", "list", "--namespace-name", "ns-a", result=["firewall-logs", "other"])
    subs = [{"id": "s1", "name": "Sub One"}, {"id": "s2", "name": "Sub Two"}]
    items = await ops.scan_event_hubs(subs, _logger(log))
    assert items == [
        ("s1", "Sub One", "rg-a", "ns-a", "firewall-logs"),
        ("s1", "Sub One", "rg-a", "ns-a", "other"),
    ]


async def test_scan_firewalls(az, log):
    az.on("network", "firewall", "list", result=[FW])
    fws = await ops.scan_firewalls("s1", "Sub One", _logger(log))
    assert fws == [FW]


# ── SAS resolution ───────────────────────────────────────────────────────────

def test_has_listen_rights():
    assert ops._has_listen_rights({"rights": ["Listen"]})
    assert ops._has_listen_rights({"rights": ["Manage", "Send"]})
    assert ops._has_listen_rights({"rights": "Listen"})
    assert not ops._has_listen_rights({"rights": ["Send"]})
    assert not ops._has_listen_rights({})


def test_with_entity_path():
    assert ops._with_entity_path("Endpoint=sb://x/;SharedAccessKey=k", "h") == "Endpoint=sb://x/;SharedAccessKey=k;EntityPath=h"
    assert ops._with_entity_path("Endpoint=sb://x/;SharedAccessKey=k;", "h") == "Endpoint=sb://x/;SharedAccessKey=k;EntityPath=h"
    assert ops._with_entity_path("Endpoint=sb://x/;EntityPath=other", "h") == "Endpoint=sb://x/;EntityPath=other"


async def _no_confirm() -> bool:
    raise AssertionError("confirm_create must not be called")


async def test_resolve_sas_prefers_named_entity_rule(az, log):
    az.on("eventhubs", "eventhub", "authorization-rule", "list", result=[
        {"name": "some-listen", "rights": ["Listen"]},
        {"name": "az-firewall-watch-listen", "rights": ["Listen"]},
    ])
    az.on("eventhubs", "eventhub", "authorization-rule", "keys", "list", result="Endpoint=sb://ns/;SharedAccessKeyName=az-firewall-watch-listen;SharedAccessKey=K\n")
    conn = await ops.resolve_sas_conn_str("s1", "rg", "ns", "h", "az-firewall-watch-listen", _logger(log), _no_confirm)
    assert conn.endswith(";EntityPath=h")
    keys_call = az.called("eventhubs", "eventhub", "authorization-rule", "keys", "list")[0]
    assert "az-firewall-watch-listen" in keys_call


async def test_resolve_sas_uses_any_entity_listen_rule(az, log):
    az.on("eventhubs", "eventhub", "authorization-rule", "list", result=[
        {"name": "send-only", "rights": ["Send"]},
        {"name": "reader", "rights": ["Listen"]},
    ])
    az.on("eventhubs", "eventhub", "authorization-rule", "keys", "list", result="Endpoint=sb://ns/;SharedAccessKeyName=reader;SharedAccessKey=K\n")
    conn = await ops.resolve_sas_conn_str("s1", "rg", "ns", "h", "wanted", _logger(log), _no_confirm)
    assert "SharedAccessKeyName=reader" in conn
    assert "reader" in az.called("eventhubs", "eventhub", "authorization-rule", "keys", "list")[0]


async def test_resolve_sas_falls_back_to_namespace_rule_but_not_root(az, log):
    az.on("eventhubs", "eventhub", "authorization-rule", "list", result=[])
    az.on("eventhubs", "namespace", "authorization-rule", "list", result=[
        {"name": "RootManageSharedAccessKey", "rights": ["Listen", "Manage", "Send"]},
        {"name": "ns-listen", "rights": ["Listen"]},
    ])
    az.on("eventhubs", "namespace", "authorization-rule", "keys", "list", result="Endpoint=sb://ns/;SharedAccessKeyName=ns-listen;SharedAccessKey=K")
    conn = await ops.resolve_sas_conn_str("s1", "rg", "ns", "h", "wanted", _logger(log), _no_confirm)
    assert "SharedAccessKeyName=ns-listen" in conn
    assert conn.endswith(";EntityPath=h")
    assert "ns-listen" in az.called("eventhubs", "namespace", "authorization-rule", "keys", "list")[0]


async def test_resolve_sas_creates_rule_after_confirmation(az, log):
    az.on("eventhubs", "eventhub", "authorization-rule", "list", result=[])
    az.on("eventhubs", "namespace", "authorization-rule", "list", result=[
        {"name": "RootManageSharedAccessKey", "rights": ["Listen", "Manage", "Send"]},
    ])
    az.on("eventhubs", "eventhub", "authorization-rule", "keys", "list", result="Endpoint=sb://ns/;SharedAccessKeyName=new;SharedAccessKey=K")
    asked: list[bool] = []

    async def _confirm() -> bool:
        asked.append(True)
        return True

    conn = await ops.resolve_sas_conn_str("s1", "rg", "ns", "h", "new", _logger(log), _confirm)
    assert asked == [True]
    create = az.called("eventhubs", "eventhub", "authorization-rule", "create")
    assert len(create) == 1
    assert "--rights" in create[0] and "Listen" in create[0]
    assert conn.endswith(";EntityPath=h")


async def test_resolve_sas_cancelled_creation_returns_empty(az, log):
    az.on("eventhubs", "eventhub", "authorization-rule", "list", result=[])
    az.on("eventhubs", "namespace", "authorization-rule", "list", result=[])

    async def _decline() -> bool:
        return False

    conn = await ops.resolve_sas_conn_str("s1", "rg", "ns", "h", "new", _logger(log), _decline)
    assert conn == ""
    assert az.called("eventhubs", "eventhub", "authorization-rule", "create") == []
    assert any("canceled" in line for line in log)


async def test_resolve_sas_creation_failure_raises(az, log):
    az.on("eventhubs", "eventhub", "authorization-rule", "list", result=[])
    az.on("eventhubs", "namespace", "authorization-rule", "list", result=[])
    az.on("eventhubs", "eventhub", "authorization-rule", "create", rc=1)

    async def _confirm() -> bool:
        return True

    with pytest.raises(subprocess.CalledProcessError):
        await ops.resolve_sas_conn_str("s1", "rg", "ns", "h", "new", _logger(log), _confirm)


# ── deployment ───────────────────────────────────────────────────────────────

@pytest.fixture
def no_sleep(monkeypatch):
    async def _sleep(_s):
        return None

    monkeypatch.setattr(ops.asyncio, "sleep", _sleep)


def _deploy_kwargs(**overrides):
    kw = dict(
        sub_id="s1", rg="rg-hub", ns="ehns-fwlogs-gwc-001", location="germanywestcentral",
        eh_name="firewall-logs", listen_rule="az-firewall-watch-listen",
        send_rule="az-firewall-watch-send", diag_name="az-firewall-watch-diag",
        fw=FW, auth_method="sas", current_user_id="oid-123", using_existing_rg=True,
    )
    kw.update(overrides)
    return kw


def _deploy_rules(az: FakeAz) -> FakeAz:
    az.on("eventhubs", "eventhub", "authorization-rule", "keys", "list", result="Endpoint=sb://ns/;SharedAccessKeyName=l;SharedAccessKey=K;EntityPath=firewall-logs\n")
    az.on("eventhubs", "namespace", "authorization-rule", "show", result="/subscriptions/s1/.../authorizationRules/az-firewall-watch-send\n")
    az.on("monitor", "diagnostic-settings", "categories", "list", result=["AZFWNetworkRule", "AZFWApplicationRule", "AZFWFlowTrace", "AzureFirewallNetworkRule"])
    return az


async def test_deploy_sas_creates_resources_in_order(az, log, no_sleep):
    _deploy_rules(az)
    conn = await ops.deploy_new_hub(log=_logger(log), **_deploy_kwargs())

    assert conn.startswith("Endpoint=sb://")
    heads = [c[:3] for c in az.calls]
    assert ("group", "create", "--subscription") not in heads  # existing RG reused
    assert heads.index(("eventhubs", "namespace", "create")) < heads.index(("eventhubs", "eventhub", "create"))
    assert heads.index(("eventhubs", "eventhub", "create")) < heads.index(("eventhubs", "eventhub", "authorization-rule"))
    assert any(c[:2] == ("monitor", "diagnostic-settings") and c[2] == "create" for c in az.calls)

    ns_create = az.called("eventhubs", "namespace", "create")[0]
    assert "--sku" in ns_create and "Basic" in ns_create
    assert "--minimum-tls-version" in ns_create and "1.2" in ns_create
    assert "project=az-firewall-watch" in ns_create

    diag = [c for c in az.calls if c[:3] == ("monitor", "diagnostic-settings", "create")][0]
    logs_json = diag[diag.index("--logs") + 1]
    cats = [entry["category"] for entry in json.loads(logs_json)]
    assert cats == ["AZFWNetworkRule", "AZFWApplicationRule", "AZFWFlowTrace"]  # only AZFW* kept
    assert "--event-hub-rule" in diag
    assert any("logs will start flowing" in line for line in log)


async def test_deploy_creates_resource_group_when_new(az, log, no_sleep):
    _deploy_rules(az)
    await ops.deploy_new_hub(log=_logger(log), **_deploy_kwargs(rg="rg-new", using_existing_rg=False))
    group = az.called("group", "create")
    assert len(group) == 1
    assert "rg-new" in group[0] and "germanywestcentral" in group[0]


async def test_deploy_entra_assigns_role_and_returns_no_secret(az, log, no_sleep):
    _deploy_rules(az)
    conn = await ops.deploy_new_hub(log=_logger(log), **_deploy_kwargs(auth_method="entra"))

    assert conn == ""
    assert az.called("eventhubs", "eventhub", "authorization-rule", "create") == []  # no Listen rule
    role = az.called("role", "assignment", "create")
    assert len(role) == 1
    assert "oid-123" in role[0]
    assert "a638d3c7-ab3a-418d-83e6-5f17a39d4fde" in role[0]  # Data Receiver role id
    scope = role[0][role[0].index("--scope") + 1]
    assert scope.endswith("/namespaces/ehns-fwlogs-gwc-001/eventhubs/firewall-logs")
    assert any("Data Receiver role assigned" in line for line in log)


async def test_deploy_entra_without_user_id_asks_for_manual_assignment(az, log, no_sleep):
    _deploy_rules(az)
    await ops.deploy_new_hub(log=_logger(log), **_deploy_kwargs(auth_method="entra", current_user_id=""))
    assert az.called("role", "assignment", "create") == []
    assert any("assign manually" in line for line in log)


async def test_deploy_entra_role_failure_is_reported_not_raised(az, log, no_sleep):
    _deploy_rules(az).on("role", "assignment", "create", rc=1)
    await ops.deploy_new_hub(log=_logger(log), **_deploy_kwargs(auth_method="entra"))
    assert any("Could not assign role automatically" in line for line in log)


async def test_deploy_diagnostics_fallback_categories_when_lookup_fails(az, log, no_sleep):
    _deploy_rules(az).rules.insert(0, ((("monitor", "diagnostic-settings", "categories", "list")), (1, "")))
    await ops.deploy_new_hub(log=_logger(log), **_deploy_kwargs())
    diag = [c for c in az.calls if c[:3] == ("monitor", "diagnostic-settings", "create")][0]
    cats = [e["category"] for e in json.loads(diag[diag.index("--logs") + 1])]
    assert "AZFWNetworkRule" in cats and "AZFWDnsQuery" in cats
    assert "AZFWFqdnResolveFailure" in cats
    assert "AZFWDnsProxy" not in cats  # not a real category
    assert all(c.startswith("AZFW") for c in cats)


async def test_deploy_diagnostics_failure_logs_manual_instructions(az, log, no_sleep):
    _deploy_rules(az).on("monitor", "diagnostic-settings", "create", rc=1)
    await ops.deploy_new_hub(log=_logger(log), **_deploy_kwargs())
    assert any("Configure manually" in line for line in log)


async def test_deploy_namespace_failure_raises(az, log, no_sleep):
    _deploy_rules(az).on("eventhubs", "namespace", "create", rc=1)
    with pytest.raises(subprocess.CalledProcessError):
        await ops.deploy_new_hub(log=_logger(log), **_deploy_kwargs())
    assert az.called("eventhubs", "eventhub", "create") == []
