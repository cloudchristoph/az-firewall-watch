"""0.6.0 point 1: explicit proxy — policy parsing, Firewall tab rows, parser flags,

the evaluation trace's refusal to guess a proxy port, and the detail dialog.
"""
from __future__ import annotations

import pytest

from fw_parser import parse_record
from viewer.arm import ArmError
from viewer.azure_resources import FirewallInfo, FirewallPolicyInfo, fetch_policy
from viewer.trace import MATCH, NA, UNKNOWN, Flow, evaluate_rule
from viewer.views.detail_screen import DetailDialog
from viewer.views.firewall import FirewallView, _explicit_proxy_rows

SUB = "/subscriptions/25ca1d83-3de5-46c7-9941-fb98c2ea026e"
POLICY_ID = f"{SUB}/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/fwp-hub"


class FakeArm:
    """Minimal stand-in for ArmClient: answers GETs from a path → payload map."""

    def __init__(self, routes: dict) -> None:
        self.routes = routes

    async def get(self, path: str, api_version: str, *, params=None) -> dict:
        if path not in self.routes:
            raise ArmError(404, "ResourceNotFound", f"no route for {path}")
        return self.routes[path]

    async def get_all(self, path: str, api_version: str, *, params=None) -> list:
        payload = self.routes.get(path, {"value": []})
        return list(payload.get("value", []))


def _policy_routes(explicit_proxy: dict | None) -> dict:
    props: dict = {}
    if explicit_proxy is not None:
        props["explicitProxy"] = explicit_proxy
    return {
        POLICY_ID: {"id": POLICY_ID, "name": "fwp-hub", "properties": props},
        f"{POLICY_ID}/ruleCollectionGroups": {"value": []},
    }


FW = FirewallInfo(id="/fw", name="fw-hub", subscription_id="s", resource_group="rg", location="gwc")


# ── policy parsing (viewer/azure_resources.py fetch_policy) ──────────────────

async def test_explicit_proxy_all_fields_present():
    routes = _policy_routes({
        "enableExplicitProxy": True,
        "httpPort": 8080,
        "httpsPort": 8443,
        "enablePacFile": True,
        "pacFilePort": 8090,
        "pacFile": "https://acct.blob.core.windows.net/c/proxy.pac?sv=2021-01-01&sig=abc123",
    })
    pol = await fetch_policy(FakeArm(routes), POLICY_ID)
    assert pol.explicit_proxy is True
    assert pol.explicit_proxy_http_port == 8080
    assert pol.explicit_proxy_https_port == 8443
    assert pol.explicit_proxy_pac is True
    assert pol.explicit_proxy_pac_port == 8090
    # the SAS token in the query string must never be kept
    assert pol.explicit_proxy_pac_file == "https://acct.blob.core.windows.net/c/proxy.pac"


async def test_explicit_proxy_all_fields_absent():
    pol = await fetch_policy(FakeArm(_policy_routes(None)), POLICY_ID)
    assert pol.explicit_proxy is False
    assert pol.explicit_proxy_http_port == 0
    assert pol.explicit_proxy_https_port == 0
    assert pol.explicit_proxy_pac is False
    assert pol.explicit_proxy_pac_port == 0
    assert pol.explicit_proxy_pac_file == ""


async def test_explicit_proxy_ports_as_strings_or_null():
    routes = _policy_routes({
        "enableExplicitProxy": True,
        "httpPort": "8080",
        "httpsPort": None,
        "pacFilePort": "8090",
        "pacFile": None,
    })
    pol = await fetch_policy(FakeArm(routes), POLICY_ID)
    assert pol.explicit_proxy_http_port == 8080
    assert pol.explicit_proxy_https_port == 0
    assert pol.explicit_proxy_pac_port == 8090
    assert pol.explicit_proxy_pac_file == ""


async def test_explicit_proxy_pac_file_without_query_string_is_kept_as_is():
    routes = _policy_routes({"pacFile": "https://acct.blob.core.windows.net/c/proxy.pac"})
    pol = await fetch_policy(FakeArm(routes), POLICY_ID)
    assert pol.explicit_proxy_pac_file == "https://acct.blob.core.windows.net/c/proxy.pac"


# ── Firewall tab rows (_explicit_proxy_rows) ──────────────────────────────────

def _policy(**kw) -> FirewallPolicyInfo:
    base = dict(id=POLICY_ID, name="fwp-hub")
    base.update(kw)
    return FirewallPolicyInfo(**base)


def test_proxy_off():
    assert _explicit_proxy_rows(_policy(explicit_proxy=False)) == [
        "[dim]Explicit proxy    [/]  off",
    ]


def test_proxy_on_both_ports():
    rows = _explicit_proxy_rows(_policy(
        explicit_proxy=True, explicit_proxy_http_port=8080, explicit_proxy_https_port=8443,
    ))
    assert rows[0] == "[dim]Explicit proxy    [/]  on   [dim]HTTP port 8080 · HTTPS port 8443[/]"
    assert rows[1] == "[dim]PAC file          [/]  off"
    assert "IsExplicitProxyRequest" in rows[2]


def test_proxy_on_http_port_only_serves_both():
    rows = _explicit_proxy_rows(_policy(explicit_proxy=True, explicit_proxy_http_port=8080))
    assert rows[0] == "[dim]Explicit proxy    [/]  on   [dim]port 8080 for HTTP and HTTPS[/]"


def test_proxy_on_https_port_only():
    rows = _explicit_proxy_rows(_policy(explicit_proxy=True, explicit_proxy_https_port=8443))
    assert rows[0] == "[dim]Explicit proxy    [/]  on   [dim]HTTPS port 8443, no HTTP port[/]"


def test_proxy_on_no_port_at_all():
    rows = _explicit_proxy_rows(_policy(explicit_proxy=True))
    assert rows[0] == "[dim]Explicit proxy    [/]  on   [dim]no port set[/]"


def test_pac_enabled_with_port_and_file():
    rows = _explicit_proxy_rows(_policy(
        explicit_proxy=True, explicit_proxy_pac=True, explicit_proxy_pac_port=8090,
        explicit_proxy_pac_file="https://acct.blob.core.windows.net/c/proxy.pac",
    ))
    assert rows[1] == ("[dim]PAC file          [/]  served on port 8090   "
                        "[dim]https://acct.blob.core.windows.net/c/proxy.pac[/]")


def test_pac_enabled_no_port():
    rows = _explicit_proxy_rows(_policy(
        explicit_proxy=True, explicit_proxy_pac=True,
        explicit_proxy_pac_file="https://acct.blob.core.windows.net/c/proxy.pac",
    ))
    assert rows[1] == "[dim]PAC file          [/]  on   [dim]port not set[/]"


def test_pac_enabled_port_but_no_file():
    rows = _explicit_proxy_rows(_policy(explicit_proxy=True, explicit_proxy_pac=True, explicit_proxy_pac_port=8090))
    assert rows[1] == "[dim]PAC file          [/]  served on port 8090   [dim]no file URL set[/]"


def test_pac_disabled():
    rows = _explicit_proxy_rows(_policy(explicit_proxy=True))
    assert rows[1] == "[dim]PAC file          [/]  off"


def test_proxy_on_ends_with_note():
    rows = _explicit_proxy_rows(_policy(explicit_proxy=True))
    assert rows[-1] == ("                    [dim]proxy requests still need an application rule; "
                         "the log marks them as IsExplicitProxyRequest[/]")


def test_proxy_off_has_no_note():
    rows = _explicit_proxy_rows(_policy(explicit_proxy=False))
    assert len(rows) == 1


def test_pac_file_url_is_escaped():
    rows = _explicit_proxy_rows(_policy(
        explicit_proxy=True, explicit_proxy_pac=True, explicit_proxy_pac_port=8090,
        explicit_proxy_pac_file="https://acct.blob.core.windows.net/c/[proxy].pac",
    ))
    assert "\\[proxy]" in rows[1]
    assert "[proxy]" not in rows[1].replace("\\[proxy]", "")


def test_explicit_proxy_rows_through_firewall_view_policy():
    pol = _policy(explicit_proxy=True, explicit_proxy_http_port=8080, explicit_proxy_https_port=8443)
    out = FirewallView._policy(pol, FW)
    joined = "\n".join(out)
    assert "on   [dim]HTTP port 8080 · HTTPS port 8443[/]" in joined
    assert "IsExplicitProxyRequest" in joined


# ── parser flags (fw_parser.py, AZFWApplicationRule branch) ──────────────────

RULE_PROPS = {"Policy": "pol-hub", "RuleCollectionGroup": "rcg-app", "RuleCollection": "rc-web", "Rule": "allow-web"}


def test_parser_flags_from_json_booleans(structured_record):
    row = parse_record(structured_record(
        "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.0.1.4", DestinationPort=8080,
        Fqdn="example.com", Action="Allow", IsExplicitProxyRequest=True, IsTlsInspected=False, **RULE_PROPS,
    ))
    assert row.explicit_proxy == "yes"
    assert row.tls_inspected == "no"


@pytest.mark.parametrize("raw,expected", [("true", "yes"), ("True", "yes"), ("TRUE", "yes"),
                                          ("false", "no"), ("False", "no"), ("FALSE", "no")])
def test_parser_flags_from_strings_case_insensitive(structured_record, raw, expected):
    row = parse_record(structured_record(
        "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.0.1.4", DestinationPort=443,
        Fqdn="example.com", Action="Allow", IsExplicitProxyRequest=raw, **RULE_PROPS,
    ))
    assert row.explicit_proxy == expected


def test_parser_flags_absent_columns_stay_unknown(structured_record):
    row = parse_record(structured_record(
        "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.0.1.4", DestinationPort=443,
        Fqdn="example.com", Action="Allow", **RULE_PROPS,
    ))
    assert row.explicit_proxy == ""
    assert row.tls_inspected == ""


def test_parser_flags_unexpected_value_stays_unknown(structured_record):
    row = parse_record(structured_record(
        "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.0.1.4", DestinationPort=443,
        Fqdn="example.com", Action="Allow", IsExplicitProxyRequest="maybe", **RULE_PROPS,
    ))
    assert row.explicit_proxy == ""


def test_apprule_no_rule_matched_uses_action_reason(structured_record):
    """Denied-by-default-action AppRule rows must show the reason, like NetworkRule rows do."""
    row = parse_record(structured_record(
        "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.0.1.4", DestinationPort=443,
        Fqdn="example.com", Action="Deny", ActionReason="No rule matched. Proceeding with default action.",
    ))
    assert row.policy == "No rule matched. Proceeding with default action."
    assert row.rule_collection_group == ""


def test_apprule_with_rule_still_builds_the_usual_policy_path(structured_record):
    row = parse_record(structured_record(
        "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.0.1.4", DestinationPort=443,
        Fqdn="example.com", Action="Allow", **RULE_PROPS,
    ))
    assert row.policy == "pol-hub»rcg-app»rc-web»allow-web"


# ── evaluation trace: _port_check / evaluate_rule ─────────────────────────────

def _app_rule(**kw):
    base = dict(name="r", rule_type="ApplicationRule", source_addresses=["*"],
                destination_fqdns=["example.com"], protocols=["Https"], destination_ports=["443"])
    base.update(kw)
    from viewer.azure_resources import Rule
    return Rule(**base)


def test_port_check_unknown_for_explicit_proxy_flow():
    flow = Flow(category="AppRule", protocol="HTTPS", src_ip="10.3.5.4", dst_fqdn="example.com",
                dst_port="8080", explicit_proxy=True)
    rule = _app_rule(destination_ports=["443"])
    r = evaluate_rule(rule, flow, {})
    port_check = next(c for c in r.checks if c.name == "port")
    assert port_check.result == UNKNOWN
    assert port_check.detail == ("cannot evaluate: explicit proxy request; whether the log carries "
                                  "the proxy port or the destination port is not verified")
    assert r.verdict == UNKNOWN  # never a confident match or miss on an unverifiable port


def test_port_check_normal_when_proxy_flag_is_off():
    flow = Flow(category="AppRule", protocol="HTTPS", src_ip="10.3.5.4", dst_fqdn="example.com",
                dst_port="443", explicit_proxy=False)
    rule = _app_rule(destination_ports=["443"])
    r = evaluate_rule(rule, flow, {})
    port_check = next(c for c in r.checks if c.name == "port")
    assert port_check.result == MATCH
    assert port_check.detail == "443"
    assert r.verdict == MATCH


def test_port_check_no_port_in_log_is_still_na_not_the_proxy_message():
    flow = Flow(category="AppRule", protocol="HTTPS", src_ip="10.3.5.4", dst_fqdn="example.com", dst_port="-")
    rule = _app_rule(destination_ports=["443"])
    port_check = next(c for c in evaluate_rule(rule, flow, {}).checks if c.name == "port")
    assert port_check.result == NA


# ── app-level: detail dialog shows the explicit-proxy fields ─────────────────

def _text(widget) -> str:
    from textual.widgets import Static
    return "\n".join(str(s.content) for s in widget.query(Static))


async def test_detail_dialog_shows_explicit_proxy_fields(structured_record, firewall_id):
    from textual.widgets import DataTable

    from viewer.app import FirewallLogApp

    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        row = parse_record(structured_record(
            "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.3.5.4", SourcePort=1,
            Fqdn="example.com", DestinationPort=8080, Action="Allow",
            IsExplicitProxyRequest=True, IsTlsInspected=False,
        ))
        assert row is not None and row.explicit_proxy == "yes" and row.tls_inspected == "no"
        app._pending.append(row)
        await app._flush_rows()
        await pilot.pause()
        tbl = app.query_one("#log-table", DataTable)
        tbl.focus()
        tbl.move_cursor(row=0, animate=False)
        await pilot.pause()
        await pilot.press("enter")

        for _ in range(20):
            if isinstance(app.screen, DetailDialog):
                break
            await pilot.pause(0.05)
        assert isinstance(app.screen, DetailDialog)
        text = _text(app.screen)
        assert "Expl. proxy" in text and "yes" in text
        assert "TLS inspected" in text and "no" in text
