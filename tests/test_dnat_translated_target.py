"""The translated target of a DNAT rule on the Policy tab (issue #59)."""

from __future__ import annotations

import asyncio

from textual.content import Content

from viewer.azure_resources import Rule, RuleCollection, RuleCollectionGroup, fetch_policy
from viewer.views import PolicyView

from .test_azure_resources import POLICY_ID, FakeArm


def _summary(rule: Rule, collection_type: str = "FirewallPolicyNatRuleCollection") -> str:
    rc = RuleCollection(name="dnat", priority=100, action="Dnat", rule_collection_type=collection_type, rules=[rule])
    rcg = RuleCollectionGroup(id="/g", name="rcg", priority=1, rule_collections=[rc])
    return Content.from_markup(PolicyView()._rule_summary(rcg, rc, rule, {})).plain


def _dnat(**kw) -> Rule:
    base = dict(
        name="web-in",
        rule_type="NatRule",
        source_addresses=["*"],
        destination_addresses=["198.51.100.10"],
        destination_ports=["443"],
        protocols=["TCP"],
    )
    base.update(kw)
    return Rule(**base)


def test_a_translated_address_and_port_are_shown():
    text = _summary(_dnat(translated_address="10.0.0.4", translated_port="8443"))
    assert "Translated     10.0.0.4:8443" in text
    assert "resolved by the firewall" not in text


def test_a_translated_fqdn_is_named_and_marked_as_resolved_by_the_firewall():
    text = _summary(_dnat(translated_fqdn="app.contoso.com", translated_port="8443"))
    assert "Translated     app.contoso.com:8443" in text
    assert "FQDN, resolved by the firewall's DNS" in text


def test_without_a_port_only_the_target_is_shown():
    assert "Translated     10.0.0.4\n" in _summary(_dnat(translated_address="10.0.0.4")) + "\n"


def test_an_ipv6_literal_is_bracketed_before_a_port():
    assert "[fd00::4]:8443" in _summary(_dnat(translated_address="fd00::4", translated_port="8443"))
    assert "Translated     fd00::4" in _summary(_dnat(translated_address="fd00::4")) + "\n"


def test_a_dnat_rule_without_any_target_says_so():
    assert "Translated     not set" in _summary(_dnat())


def test_hostile_values_are_shown_as_text():
    text = _summary(_dnat(translated_fqdn="[ @click=app.quit]x[/]", translated_port="[/p]"))
    assert "[ @click=app.quit]x[/]:[/p]" in text


def test_other_rule_kinds_get_no_translated_line():
    net = Rule(name="n", rule_type="NetworkRule", destination_addresses=["*"], destination_ports=["443"])
    app = Rule(name="a", rule_type="ApplicationRule", destination_fqdns=["x.example"])
    assert "Translated" not in _summary(net, "FirewallPolicyFilterRuleCollection")
    assert "Translated" not in _summary(app, "FirewallPolicyFilterRuleCollection")


def test_the_fields_are_read_from_arm():
    group = {
        "id": f"{POLICY_ID}/ruleCollectionGroups/g",
        "name": "g",
        "properties": {
            "priority": 100,
            "ruleCollections": [
                {
                    "name": "dnat",
                    "priority": 100,
                    "ruleCollectionType": "FirewallPolicyNatRuleCollection",
                    "action": {"type": "Dnat"},
                    "rules": [
                        {
                            "name": "web-in",
                            "ruleType": "NatRule",
                            "sourceAddresses": ["*"],
                            "destinationAddresses": ["198.51.100.10"],
                            "destinationPorts": ["443"],
                            "ipProtocols": ["TCP"],
                            "translatedFqdn": "app.contoso.com",
                            "translatedPort": "8443",
                        }
                    ],
                }
            ],
        },
    }
    arm = FakeArm(
        {
            POLICY_ID: {"id": POLICY_ID, "name": "p", "properties": {}},
            f"{POLICY_ID}/ruleCollectionGroups": {"value": [group]},
        }
    )
    pol = asyncio.run(fetch_policy(arm, POLICY_ID))
    rule = pol.rule_collection_groups[0].rule_collections[0].rules[0]
    assert rule.translated_fqdn == "app.contoso.com" and rule.translated_port == "8443" and not rule.translated_address
