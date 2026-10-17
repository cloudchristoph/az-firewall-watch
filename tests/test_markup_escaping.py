"""ARM and log text in markup: shown as written, never parsed as a tag.

Rich's ``escape`` only escapes ``[`` followed by a lower-case letter, ``#``,
``/`` or ``@``; Textual opens a tag at any unescaped ``[``. These payloads got
through Rich's escape into a ``Static`` and either crashed the Firewall tab
(``MarkupError`` on every start while the tag existed) or rendered a click
action or a terminal hyperlink.
"""
from __future__ import annotations

import pytest
from rich.text import Text
from textual.app import App, ComposeResult
from textual.content import Content
from textual.widgets import Static

from fw_parser import FirewallDataRow
from helpers import escape_markup, escape_rich_markup
from viewer.azure_resources import FirewallInfo, FirewallPolicyInfo, Rule, RuleCollection, RuleCollectionGroup
from viewer.views import FirewallView, PolicyView
from viewer.views.detail_screen import _border_title, _header_line1
from viewer.views.firewall import _row

PAYLOADS = [
    "[/x",
    "[ @click=app.quit]Update[/]",
    "[X=:]",
    "[$var]",
    '[link="https://e"]x[/]',
    '[ link="https://evil.example"]Security notice[/]',
    "[@click=app.quit]lower[/]",
    "[b]bold[/b]",
    "a\\[b]c",
    "[[nested]]",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_escape_markup_renders_literally_in_textual(payload):
    content = Content.from_markup(f"[dim]k[/] {escape_markup(payload)} [b]v[/b]")
    assert content.plain == f"k {payload} v"


@pytest.mark.parametrize("payload", PAYLOADS)
def test_escape_rich_markup_renders_literally_in_rich(payload):
    text = Text.from_markup(f"[dim]k[/] {escape_rich_markup(payload)} [b]v[/b]")
    assert text.plain == f"k {payload} v"


def test_a_trailing_backslash_does_not_escape_the_next_tag():
    # Without the guard the value's "\" would turn the template's "[/]" into
    # text and leave "[dim]" open, or an auto-close with nothing to close.
    for template in ("[dim]{v}[/]", "{v}[dim]x[/]", "[b]{v}[/b] [dim]y[/]"):
        content = Content.from_markup(template.format(v=escape_markup("x\\")))
        assert "[" not in content.plain and "x\\" in content.plain


def test_ordinary_values_are_unchanged():
    for value in ("fw-hub-gwc", "10.2.0.4", "fd10:3:5:1::4", "https://example.com/a?b=c", "allow-web (rc)"):
        assert escape_markup(value) == value
        assert escape_rich_markup(value) == value


def test_bracketed_ipv6_keeps_its_brackets():
    assert Content.from_markup(escape_markup("[fd10::4]:443")).plain == "[fd10::4]:443"


# ── the Firewall tab's real render path ──────────────────────────────────────

class _FirewallApp(App):
    def compose(self) -> ComposeResult:
        yield FirewallView(id="firewall-view")


def _plain(widget: Static) -> str:
    visual = widget.visual
    return visual.plain if isinstance(visual, Content) else str(visual)


async def test_firewall_tab_shows_hostile_tags_and_names_as_text():
    tags = {f"t{i}": payload for i, payload in enumerate(PAYLOADS)}
    tags["[/key"] = "v"
    fw = FirewallInfo(id="/fw", name="fw[/x", subscription_id="s", resource_group="rg[X=:]", location="gwc",
                      sku_tier="Premium", tags=tags, provisioning_state="[ @click=app.quit]Failed[/]",
                      additional_properties={"Custom.Key": "[/x", "Network.SNAT.PrivateRanges": "[$var]"},
                      private_ips=["10.2.0.4"])
    policy = FirewallPolicyInfo(id="/p", name="[/policy", sku_tier="Premium", threat_intel_mode="[X=:]",
                                dns_proxy=True, dns_servers=["[/dns"], tls_ca_name='[link="https://e"]ca[/]')
    app = _FirewallApp()
    async with app.run_test(size=(200, 60)) as pilot:
        view = app.query_one(FirewallView)
        view.render_data(fw, policy, ["10.2.0.0/26"])
        await pilot.pause()
        instance = _plain(view.query_one("#fw-instance", Static))
        for payload in PAYLOADS:
            assert payload in instance
        assert "[/key=v" in instance
        assert "[ @click=app.quit]Failed[/]" in instance
        assert "Custom.Key=[/x" in instance and "[$var]" in instance
        assert _plain(view.query_one("#fw-title", Static)).startswith("fw[/x")
        policy_text = _plain(view.query_one("#fw-policy", Static))
        assert "[/policy" in policy_text and "[/dns" in policy_text and '[link="https://e"]ca[/]' in policy_text


async def test_firewall_tab_shows_a_hostile_error_reason_as_text():
    app = _FirewallApp()
    async with app.run_test(size=(160, 40)) as pilot:
        view = app.query_one(FirewallView)
        view.render_unavailable("denied [/x\nsecond [ @click=app.quit]line[/]")
        await pilot.pause()
        text = _plain(view.query_one("#fw-error", Static))
        assert "denied [/x\nsecond [ @click=app.quit]line[/]" in text


def test_row_width_follows_the_textual_parse():
    # _row measures the value to align the detail column; an escaped "[" is
    # one cell, not two, and a Rich-only parse would choke on "\\[/x".
    narrow = _row("Label", escape_markup("[on]"), "detail")
    assert Content.from_markup(narrow).plain.endswith("[on]" + " " * 10 + "detail")
    _row("Label", escape_markup("\\[/x]"), "detail")


# ── Policy tab and detail dialog formatting ──────────────────────────────────

def test_policy_rule_summary_shows_hostile_names_as_text():
    rule = Rule(name="[/rule", rule_type="ApplicationRule", protocols=["[X=:]"],
                destination_fqdns=["[ @click=app.quit]x[/]"], source_addresses=["[$var]"])
    rule.http_headers = []
    rc = RuleCollection(name="[/rc", priority=100, action="Allow", rule_collection_type="Filter", rules=[rule])
    rcg = RuleCollectionGroup(id="/g", name='[link="https://e"]g[/]', priority=1, rule_collections=[rc])
    summary = PolicyView()._rule_summary(rcg, rc, rule, {})
    plain = Content.from_markup(summary).plain
    for value in ("[/rule", "[X=:]", "[ @click=app.quit]x[/]", "[$var]", "[/rc", '[link="https://e"]g[/]'):
        assert value in plain


def test_detail_border_title_is_textual_safe():
    row = FirewallDataRow(rowid="1", time="t", category="[/x")
    assert Content.from_markup(_border_title(row, None)).plain == "[/x"
    row = FirewallDataRow(rowid="1", time="t", category="NetworkRule", action="[ @click=app.quit]x[/]")
    assert Content.from_markup(_border_title(row, None)).plain == "[ @CLICK=APP.QUIT]X[/]"


def test_detail_header_is_rich_safe():
    row = FirewallDataRow(rowid="1", time="t", category="AppRule", protocol="[/x", sourceip="10.0.0.1",
                          srcport="1", targetip='[link="https://e"]evil[/]', targetport="443", action="Allow")
    plain = Text.from_markup(_header_line1(row)).plain
    assert '[link="https://e"]evil[/]' in plain and "[/x" in plain
