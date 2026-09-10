# Row detail dialog: redesign plan

Status: done, shipped with 0.6.0. Source: a Codex review of the dialog as it
stood after the 0.6.0 tabs work, reduced to what the code and the data can
actually support. All seven packages below have landed.

The dialog is what `Enter` opens on a log row. Today it is two things glued
together: the row's fields on the left, and, when policy context is on and the
metadata is loaded, the evaluation trace on the right. The review's complaint
is fair: too much text of equal weight, long resource names, a `nearest miss`
suffix on every collection, the logged rule somewhere in the middle, and a
blue frame that shouts. This plan fixes that without changing a single verdict.

## Ground rules

- **Works with and without policy context.** `POLICY_CONTEXT=off` means the
  dialog is the row's fields, a footer and nothing else: no trace column, no
  policy vocabulary, no empty right pane. The same dialog class serves both,
  the layout follows what is available. Every test below runs in both modes.
- **No verdict changes.** `viewer/trace.py` stays untouched. The dialog only
  renders `Trace`, `Check` and `RuleTrace`; `MATCH` / `MISS` / `UNKNOWN` / `NA`
  and the evaluation order are not this plan's business.
- **What the log says and what the viewer computed stay visually apart.**
  "Logged: Allow by …" is the firewall's word; every ✓ ✗ ? below it is ours.
- **Nothing sensitive appears by itself.** Header values stay hidden until
  asked for, as in the Policy tab.
- **Read-only, no Azure, no new dependencies.** Textual and Rich as they are.

## Layout

```
┌ Log entry · AppRule ───────────────────────────────────────────────────┐
│ 10.3.11.4:41644 → www.petmd.com:443   HTTPS   Allow                     │  header, once
│ Logged rule: allow-outbound-web-traffic        cached policy · 12 min   │  only with a trace
├───────────────────────────┬────────────────────────────────────────────┤
│ Connection                │ Threat Intelligence       Alert · no hit   │
│   Time     18:41:46 local │ ▸ DNAT                    no match         │
│            16:41:46 UTC   │ ▸ Network                 no certain match │
│   Ports    41644 → 443    │ ▾ Application             matched          │
│ Inspection                │   ▾ [100] cclab-application-rule-…         │
│   Explicit proxy  no      │     ▸ 9 preceding collections              │
│   TLS inspected   no      │     ▾ [200] outbound-access-demo-app-rules │
│ Groups                    │       ✓ allow-outbound-web-traffic  LOGGED │
│   src  ipgroup-all-spokes │                                            │
│        ipgroup-spoke-…    ├────────────────────────────────────────────┤
│                           │ allow-outbound-web-traffic   allow          │  selection detail
│                           │ ✓ source       10.3.11.4 ∈ ipgroup-all-…    │
│                           │ ✓ destination  www.petmd.com               │
│                           │ ✓ port         443                          │
│                           │ ✓ protocol     HTTPS                        │
├───────────────────────────┴────────────────────────────────────────────┤
│ Enter expand · p Policy tab · a all/focused · v values · Esc close      │  footer
└─────────────────────────────────────────────────────────────────────────┘
```

Without policy context, or before the metadata is loaded, the right two thirds
do not exist: the dialog is the left column at its natural width, with the
footer reduced to `Esc close`, and under the fields the one-line reason from
0.6.0 (*No rule decision in this log* / *Policy trace not available*).

## Work packages

Each is one subagent brief with tests of its own; they build on each other in
this order.

1. ✓ **Header and footer** (`viewer/views/detail_screen.py`)
   One header line with connection, protocol and logged action, built from
   the row alone so it exists in both modes. Second line only with a trace:
   the logged rule (or *no rule in the log*) and the cache age from the
   snapshot. Footer replaces the Close button; keys shown depend on what is
   present. Border thin, `$panel` instead of `$primary`.
   Tests: header equal in both modes; second line absent without a trace;
   footer keys per mode; no key leaks to the app on close.

2. ✓ **Left column in groups** (`viewer/views/detail_screen.py`)
   *Connection* (time local and UTC, source, destination, ports, and the
   category-specific fields: Flag, Rate, Response, Query type, Threat,
   Signature), *Inspection* (explicit proxy, TLS inspected, only when the
   record carries them), *Groups* (IP groups one per line). Values that the
   header already shows are not repeated. Long values stay on their own line
   only when they would not fit the column; the threshold follows the width.
   Tests: one test per category with the expected groups; IPv6 endpoints;
   a 60-entry IP group list stays scrollable.

3. ✓ **Focused tree** (`viewer/views/trace_screen.py`)
   Tree lines are status, priority and name only; collection lines lose the
   `n rules · nearest miss: …` suffix, rule lines lose the inline check
   summary. Collections before the logged rule's collection collapse into one
   line `▸ n preceding collections` (expandable), collections after it into
   `▸ n not evaluated`. A `?` anywhere in a collapsed range keeps that range
   open one level, so unknowns never disappear. `a` toggles the full tree.
   The logged rule is selected and scrolled into view on open.
   Tests: node labels contain no `nearest miss`; the logged node is the
   cursor node after open; unknown collections are visible in focused mode;
   `a` and back; inherited policies keep their `· policy` origin.

4. ✓ **Selection detail under the tree** (`viewer/views/trace_screen.py`)
   A `Static` under the tree that follows the cursor: for a rule its full
   name, collection, group, action, then one line per check with the
   observed value and the rule's expectation as the trace already records
   them (`Check.detail`), for a collection its verdict and reason, for a
   pass its note. Header names of an inserting rule appear here, values do
   not. Long names are cut in the tree with `…`, whole in the detail.
   Tests: cursor moves update the detail; every `Check.detail` reaches the
   detail verbatim; header values absent.

5. ✓ **Keys** (`viewer/views/trace_screen.py`, `viewer/app.py`)
   `Enter` toggles a node, nothing else. `p` opens the selected rule in the
   Policy tab (dismisses with the rule ref as today). `a` full tree,
   `v` has no meaning here (values live in the Policy tab). `Esc`/`q` close
   and stop the event. The footer lists exactly these.
   Tests: `Enter` on an open rule no longer leaves the dialog; `p` does;
   `q` inside the dialog does not quit the app.

6. ✓ **Small terminals** (`viewer/views/detail_screen.py`)
   Below 120 columns the two columns become tabs inside the dialog
   (*Fields* / *Policy trace*, `Tab` switches); below 30 rows the tree gets
   the space and the selection detail collapses to its name lines. Every pane
   scrolls on its own; nothing is cut off.
   Tests: 160×45 side by side, 120×30 side by side with the selection detail
   shortened, 80×24 tabs with scrolling; the
   logged rule reachable at all three sizes; without policy context the
   dialog is the fields alone at all three sizes.

7. ✓ **Colour** (both files)
   ✓ green, ? yellow, ✗ dim (a miss is the normal case), not-evaluated
   dimmer still; `deny` stays loud red, `allow` the quiet green from 0.6.0.
   Every symbol and colour name goes through the same rendering path (Rich
   Text, see 0.6.0) so the legend matches the tree. Selection uses
   `$surface-lighten-2` rather than the saturated primary.
   Tests: SVG colour check like the 0.6.0 one, in the flexoki theme and in
   `textual-light`.

## Out of scope

- A candidate-rule search for observation rows (FatFlow, FlowTrace): that is
  the roadmap's *related events* item, a feature of its own.
- Any change to `viewer/trace.py`.
- The Policy tab and the Firewall tab.

## Done when

- All seven packages merged, `pytest` at least the 0.6.0 count plus the
  tests above, `ruff` and `mypy` clean.
- Screenshots at 160×45, 120×30 and 80×24, each with and without policy
  context, in the PR.
- `docs/using-the-viewer.md` and `docs/policy-context.md` describe the new
  keys and layout; the CHANGELOG lists the key changes under *Changed*.
