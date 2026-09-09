"""Package 7 of docs/detail-dialog-plan.md: colour and visual weight.

A miss is the normal case for most rules, so ✗ is dim, not an alarm; ? stays
the loudest mark since it is the one thing the viewer cannot resolve itself;
not-evaluated collections are dimmer still; the tree's selection reads without
shouting. Every one of those decisions lives in Rich markup (``[green]``,
``[dim]``, ...), and Rich colour *names* only become actual pixels once the
running app renders them through its ANSI theme — so the only honest way to
check "this mark is this colour, and that mark is a different one" is to
render the real dialog and read the exported SVG back, the way 0.6.0 checked
its own colours.

Two kinds of check:
* Unit tests on the plain building blocks (``_action_tag``, ``_ICON``,
  ``LEGEND``) — no rendering needed, they are just strings.
* SVG tests on a real trace that produces a match, a miss, an unresolved
  check and a not-evaluated collection all at once, in both the app's default
  theme (flexoki) and ``textual-light``.
"""
from __future__ import annotations

import html
import re
import time
from collections import Counter

import pytest
from textual.widgets import DataTable, Tree

from fw_parser import parse_record
from viewer.app import FirewallLogApp
from viewer.azure_resources import (
    FirewallInfo,
    FirewallPolicyInfo,
    Rule,
    RuleCollection,
    RuleCollectionGroup,
)
from viewer.cache import CachedSnapshot
from viewer.trace import MATCH, MISS, NA, UNKNOWN
from viewer.views.detail_screen import DetailDialog
from viewer.views.trace_screen import _ICON, LEGEND, _action_tag

from .test_views import _load, no_update_check, wait_until  # noqa: F401  (no_update_check is a pytest fixture)
from .test_views import mgmt as _mgmt  # noqa: F401  (pytest fixture, wrapped below)

pytestmark = pytest.mark.usefixtures("no_eventhub_env", "no_update_check")


@pytest.fixture
def mgmt(_mgmt):  # noqa: F811  (re-bound so it can be used as a test parameter name)
    return _mgmt


# ── unit tests: the plain building blocks ─────────────────────────────────────

def test_action_tag_weights():
    """deny loud, allow quiet, dnat in between — 0.6.0's weights, unchanged."""
    assert _action_tag("Deny", "network") == "[bold red]deny[/]"
    assert _action_tag("Allow", "network") == "[dim green]allow[/]"
    assert _action_tag("Dnat", "network") == "[bold yellow]dnat[/]"
    assert _action_tag("", "dnat") == "[bold yellow]dnat[/]"  # kind alone is enough
    assert _action_tag("Something", "network") == "[dim]something[/]"


def test_icon_weights():
    """A miss is dim (the ordinary case); ? stays the one mark that pops."""
    assert _ICON[MATCH] == "[green]✓[/]"
    assert _ICON[MISS] == "[dim]✗[/]"
    assert _ICON[UNKNOWN] == "[yellow]?[/]"
    assert _ICON[NA] == "[dim]–[/]"


def test_legend_matches_the_new_weights():
    assert LEGEND == "[green]✓[/] match   [dim]✗ miss[/]   [yellow]?[/] cannot evaluate   [dim]– not in log[/]"


# ── a trace with one of everything ────────────────────────────────────────────

def _colour_snapshot() -> CachedSnapshot:
    """One application group: a miss (deny-tagged, so it also gives us a
    ``deny`` tag to contrast against), an FQDN-tag rule the trace cannot
    evaluate (?), the logged match, and a collection after it that is never
    evaluated — a ✓, a ✗, a ? and a not-evaluated collection in one trace."""
    fw = FirewallInfo(id="/fw", name="fw", subscription_id="s", resource_group="rg", location="gwc",
                      sku_tier="Premium")
    group = RuleCollectionGroup(id="/p/app", name="rcg-app-demo", priority=100, rule_collections=[
        RuleCollection(name="rc-app-miss", priority=10, action="Deny", rule_collection_type="Filter", rules=[
            Rule(name="app-miss", rule_type="ApplicationRule", source_addresses=["*"],
                 destination_fqdns=["other.example.com"], destination_ports=["443"], protocols=["Https"]),
        ]),
        RuleCollection(name="rc-app-unknown", priority=20, action="Allow", rule_collection_type="Filter", rules=[
            Rule(name="app-fqdntag", rule_type="ApplicationRule", source_addresses=["*"],
                 fqdn_tags=["AzureBackup"], destination_ports=["443"], protocols=["Https"]),
        ]),
        RuleCollection(name="rc-app-match", priority=30, action="Allow", rule_collection_type="Filter", rules=[
            Rule(name="app-match", rule_type="ApplicationRule", source_addresses=["*"],
                 destination_fqdns=["www.example.com"], destination_ports=["443"], protocols=["Https"]),
        ]),
        RuleCollection(name="rc-app-after", priority=40, action="Allow", rule_collection_type="Filter", rules=[
            Rule(name="app-after", rule_type="ApplicationRule", source_addresses=["*"],
                 destination_fqdns=["later.example.com"], destination_ports=["443"], protocols=["Https"]),
        ]),
    ])
    policy = FirewallPolicyInfo(id="/p", name="fwp-colour", sku_tier="Premium", threat_intel_mode="Off",
                                rule_collection_groups=[group])
    return CachedSnapshot(firewall=fw, policy=policy, ip_groups={}, fetched_at=time.time())


def _colour_row(structured_record):
    return parse_record(structured_record(
        "AZFWApplicationRule", Protocol="HTTPS", SourceIp="10.3.5.4", SourcePort=1, DestinationPort=443,
        Fqdn="www.example.com", Action="Allow", Policy="fwp-colour", RuleCollectionGroup="rcg-app-demo",
        RuleCollection="rc-app-match", Rule="app-match",
    ))


def _walk(node):
    out = [node]
    for child in node.children:
        out.extend(_walk(child))
    return out


async def _open_colour_trace(app, pilot, structured_record) -> DetailDialog:
    row = _colour_row(structured_record)
    app._pending.append(row)
    await app._flush_rows()
    await pilot.pause()
    tbl = app.query_one("#log-table", DataTable)
    tbl.focus()
    tbl.move_cursor(row=0, animate=False)
    await pilot.pause()
    await pilot.press("enter")
    await wait_until(pilot, lambda: isinstance(app.screen, DetailDialog) and app.screen.has_trace)
    await pilot.pause(0.2)
    await pilot.press("a")  # full tree: every collapsed fold — and its ? / ✗ — becomes visible
    await pilot.pause(0.2)
    return app.screen


def _node(tree: Tree, predicate):
    return next(n for n in _walk(tree.root) if predicate(n.label.plain))


# ── SVG colour reading ────────────────────────────────────────────────────────
# Textual's SVG export turns every distinct resolved style into its own CSS
# class ("...-r7 { fill: #rrggbb }") and renders each run of same-styled text
# as one <text class="...-r7">…</text>. Rich markup colour *names* only become
# real pixels here — this is the one place that can tell two "dim"s or two
# "green"s apart.

_TEXT_RE = re.compile(r'<text class="([\w-]+)"[^>]*>([^<]*)</text>')
_FILL_RE = re.compile(r'\.([\w-]+)\s*\{\s*fill:\s*(#[0-9a-fA-F]{6})')
_RECT_FILL_RE = re.compile(r'<rect fill="(#[0-9a-fA-F]{6})"')


def _decode(raw: str) -> str:
    return html.unescape(raw).replace("\xa0", " ")


def _fill_by_class(svg: str) -> dict[str, str]:
    return dict(_FILL_RE.findall(svg))


def _background_fill(svg: str) -> str:
    """The single most common background rect fill — the page's own ground,
    which no glyph may end up matching (that would mean it is invisible)."""
    return Counter(_RECT_FILL_RE.findall(svg)).most_common(1)[0][0]


def _glyph_fills(svg: str, glyph: str) -> set[str]:
    """Every distinct fill colour used to draw *glyph*.

    A glyph starts its own <text> run when nothing after it shares its style
    (the common case — see LEGEND's bare "✓"); it stays in a combined run
    with the word after it when that word shares the same style (LEGEND's
    "✗ miss", "– not in log", and the pass summaries' "✓ matched" /
    "✗ no match"). Both are recognised: the run must start with the glyph,
    and either be exactly the glyph or continue with a space.
    """
    fills = _fill_by_class(svg)
    found: set[str] = set()
    for cls, raw in _TEXT_RE.findall(svg):
        text = _decode(raw)
        if text == glyph or (text.startswith(glyph) and len(text) > len(glyph)
                             and text[len(glyph)] == " "):
            fill = fills.get(cls)
            if fill:
                found.add(fill)
    return found


def _icon_fills_before_label(svg: str, label: str) -> set[str]:
    """The fill of whatever glyph immediately precedes a check-name run.

    ``Check.name`` values ("source", "destination", "port", "protocol") are
    unique to the selection detail — the tree never renders them — so this
    is how a detail-pane icon is found without depending on screen geometry.
    The name is left-padded to 12 columns and, sharing the same (plain) style
    as the check's own detail text right after it, ends up merged into one
    run with that detail — "destination  www.example.com not in ..." — so
    this matches on the label leading the (stripped) run, not full equality.
    """
    fills = _fill_by_class(svg)
    runs = [(cls, _decode(raw)) for cls, raw in _TEXT_RE.findall(svg)]
    label_re = re.compile(rf"^{re.escape(label)}(\s|$)")
    found: set[str] = set()
    for i, (_cls, text) in enumerate(runs):
        if label_re.match(text.lstrip()) and i > 0:
            icon_cls, icon_text = runs[i - 1]
            if icon_text.strip() in ("✓", "✗", "?", "–"):
                fill = fills.get(icon_cls)
                if fill:
                    found.add(fill)
    return found


def _deny_tag_fills(svg: str) -> set[str]:
    fills = _fill_by_class(svg)
    found: set[str] = set()
    for cls, raw in _TEXT_RE.findall(svg):
        if _decode(raw).strip() == "deny":
            fill = fills.get(cls)
            if fill:
                found.add(fill)
    return found


async def _capture(app, pilot, node) -> str:
    """Move the cursor to *node* and export the screen as SVG.

    The cursor's own row is styled for legibility (see TracePanel.DEFAULT_CSS)
    and would otherwise report a third, unrelated colour for whatever glyph
    sits on it — so every capture below parks the cursor on a row that carries
    none of the glyphs being measured in that capture.
    """
    tree = app.screen.query_one("#trace-tree", Tree)
    tree.move_cursor(node)
    await pilot.pause(0.2)
    return app.export_screenshot()


async def _assert_weights_hold(app, pilot, structured_record) -> None:
    screen = await _open_colour_trace(app, pilot, structured_record)
    tree = screen.query_one("#trace-tree", Tree)

    # 1) Tree + legend: park the cursor on a glyph-free row (Threat
    # Intelligence carries no ✓/✗/? of its own) so nothing here is tainted
    # by the cursor's own style, then read every mark at once.
    neutral = _node(tree, lambda label: label.strip().startswith("Threat Intelligence"))
    svg = await _capture(app, pilot, neutral)

    match_fill = _glyph_fills(svg, "✓")
    miss_fill = _glyph_fills(svg, "✗")
    unknown_fill = _glyph_fills(svg, "?")
    assert len(match_fill) == 1, f"✓ should render as one colour everywhere, found {match_fill}"
    assert len(miss_fill) == 1, f"✗ should render as one colour everywhere, found {miss_fill}"
    assert len(unknown_fill) == 1, f"? should render as one colour everywhere, found {unknown_fill}"
    assert match_fill != miss_fill and miss_fill != unknown_fill and match_fill != unknown_fill

    background = _background_fill(svg)
    assert next(iter(match_fill)) != background
    assert next(iter(miss_fill)) != background
    assert next(iter(unknown_fill)) != background

    deny_fill = _deny_tag_fills(svg)
    assert deny_fill, "expected at least one rendered 'deny' tag"
    assert next(iter(miss_fill)) not in deny_fill  # a miss must never read as loud as a denial

    # 2) Selection detail: the miss rule's checks show a real ✗ (destination)
    # next to real ✓s (source, port, protocol) — neither is on the tree's
    # cursor row, since the cursor is a Tree concept and this Static is not
    # part of the Tree.
    miss_rule = _node(tree, lambda label: label.strip() == "✗ app-miss")
    svg_miss = await _capture(app, pilot, miss_rule)
    assert _icon_fills_before_label(svg_miss, "destination") == miss_fill
    assert _icon_fills_before_label(svg_miss, "source") == match_fill

    # 3) The FQDN-tag rule the trace cannot evaluate: its destination check
    # is the ? in the detail pane.
    unknown_rule = _node(tree, lambda label: label.strip() == "? app-fqdntag")
    svg_unknown = await _capture(app, pilot, unknown_rule)
    assert _icon_fills_before_label(svg_unknown, "destination") == unknown_fill


async def test_glyph_weights_are_distinct_and_consistent_flexoki(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = _colour_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        assert app.theme == "flexoki"  # the app's own default; not this test's business to set it
        await _assert_weights_hold(app, pilot, structured_record)


async def test_glyph_weights_are_distinct_and_consistent_textual_light(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = _colour_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        app.theme = "textual-light"
        await pilot.pause()
        await _assert_weights_hold(app, pilot, structured_record)


# ── the not-evaluated collection: dim as a whole, never a miss ───────────────

async def test_not_evaluated_collection_is_dim_as_a_whole_not_red(structured_record, mgmt, firewall_id):
    mgmt["snapshot"] = _colour_snapshot()
    app = FirewallLogApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        await _load(app, pilot, firewall_id)
        screen = await _open_colour_trace(app, pilot, structured_record)
        tree = screen.query_one("#trace-tree", Tree)
        after = _node(tree, lambda label: label.strip().startswith("– [40] rc-app-after"))
        svg = await _capture(app, pilot, after)
        na_fill = _glyph_fills(svg, "–")
        deny_fill = _deny_tag_fills(svg)
        assert na_fill and deny_fill
        assert not (na_fill & deny_fill)  # dim, never mistaken for the loud deny tag
