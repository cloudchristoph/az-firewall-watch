---
name: code-review
description: Review guidance for az-firewall-watch, a read-only Azure Firewall log viewer whose central promise is that it never states a verdict it cannot support. Use when reviewing any pull request in this repository.
---

# Reviewing az-firewall-watch

A terminal viewer (Textual TUI) that streams Azure Firewall diagnostic records from an
Event Hub, and, when policy context is switched on, reads the firewall, its policy chain
and the referenced IP groups from ARM to explain which rule a log row matched.

The product is an explanation, not a dashboard. That shapes what a defect is here: a
sentence the tool states with confidence and cannot back up is a worse bug than a missing
feature, a slow redraw, or an ugly layout. Review accordingly.

## The rule that outranks all others

`viewer/trace.py` marks every criterion of every rule with one of four results:

| Result | Meaning |
| --- | --- |
| `MATCH` | the criterion is satisfied, and the data proves it |
| `MISS` | the criterion is not satisfied, and the data proves it |
| `UNKNOWN` | it cannot be decided from the log and the cached policy |
| `NA` | the log row carries nothing to decide it with |

**Anything that cannot be decided locally must be `UNKNOWN`, never `MATCH` and never
`MISS`.** A user reads a `✗` as "this rule did not fire" and goes looking elsewhere. If
that `✗` was a guess, the tool has actively sent them the wrong way.

Flag these patterns, in changed code and in code the diff touches:

- `except ValueError: continue` (or any bare skip) while parsing addresses, rule fields or
  policy data. Dropping an entry silently shrinks the set being matched against and turns
  an unmatched lookup into a confident `MISS`. Unparseable input must reach the user as
  `UNKNOWN` naming the entry.
- A new criterion that returns `MISS` when its input is absent or unreadable, rather than
  `UNKNOWN` or `NA`.
- Comparing a field Azure does not actually use for that decision. Being right by
  coincidence is still a bug here.
- Widening an `UNKNOWN` into a `MATCH`/`MISS` without a source. If a change makes the tool
  claim *more* than before, the PR description must say so and justify it.

## Azure semantics that have already caused wrong verdicts

Check claims against the linked docs rather than against intuition. Each of these has
produced a real defect in this repository.

- **Application rules match on the `Host` header (HTTP) or the SNI (HTTPS), and the
  firewall ignores the packet's destination IP** in favour of the address it resolved from
  the name ([rule processing](https://learn.microsoft.com/azure/firewall/rule-processing#outbound-connectivity)).
  Comparing the logged destination IP against an application rule cannot be correct.
  `destinationAddresses` is nonetheless a valid field on `ApplicationRule`, so its presence
  makes the criterion undecidable rather than irrelevant.
- **IP groups and rule address lists accept three notations**: a single address, a CIDR
  block, and an inclusive range `10.2.0.0-10.2.0.31`
  ([IP groups](https://learn.microsoft.com/azure/firewall/ip-groups)). All three must be
  understood everywhere addresses are parsed, for IPv4 and IPv6.
- **Network rules with FQDN targets** are resolved by the firewall's own DNS, and that
  resolution is not in the log. Comparing a logged IP against them is undecidable.
- **Service tags, FQDN tags, web categories and target URLs** cannot be resolved locally.
  FQDN tags cannot be resolved at all: Azure publishes only the tag names.
- **Evaluation order** is Threat Intelligence, then DNAT, network, application rules,
  inherited parent policy first, by priority, stopping at the first match. A change that
  reorders or short-circuits this needs a test.

## Read-only is a hard constraint, not a preference

The tool never changes anything in Azure. `viewer/arm.py` deliberately exposes only `get`
and `get_all`, both issuing `GET`.

- Flag any `POST`, `PUT`, `PATCH` or `DELETE` against ARM, including long-running
  "action" endpoints such as `learnedIPPrefixes`, which require permissions beyond Reader.
- Suggested remediations are shown as a command to copy, never executed.
- New reads should stay within Reader. A change that needs a broader role deserves a
  comment even when it works.

## Secrets can leave the screen

`Ctrl+S` saves an SVG of the current screen, and those files end up in tickets and chat.
Everything rendered is potentially published.

- Flag rendering of Event Hub connection strings, SAS keys, ARM tokens, and the values of
  HTTP header insertion rules, which by Microsoft's own documentation may carry
  authentication tokens and tenant identifiers.
- `helpers._parse_eventhub_endpoint` returns namespace and hub and deliberately never the
  key. Keep it that way.
- Prefer showing names and revealing values only on request.

## The legacy parser is positional and fragile

`fw_parser.py` parses two formats: structured records, and the legacy `properties.msg`
free text, which it splits by word index and separator.

- Never split a `host:port` token with `split(":")`. IPv6 breaks it. Use
  `helpers.split_endpoint` and `helpers.format_endpoint`, which handle the bracketed and
  the unbracketed form and document the ambiguity in `fd00::1:1234`.
- A malformed record must degrade to a skipped row, never raise into the Event Hub
  consumer and never stall the stream.
- Word-index changes need a fixture built from a real record, not from the comment above
  the code.

## Performance shape

- Functions in `viewer/enrichment.py` and `viewer/trace.py` run per table row and per rule
  on the path. Allocation and parsing there is multiplied by thousands.
- Parse helpers are cached with `lru_cache` keyed by tuples. Keep new helpers hashable and
  keep the cache on the parse step, not on the per-row question.
- Prefer comparing range endpoints over expanding a range into networks. A `/8` written as
  a range would otherwise materialise a very large list.

## Tests and gates

- `pytest` must stay green, `ruff check .` and `mypy` clean. Python 3.10 is the floor, so
  no syntax or typing that needs a later version at runtime.
- Evaluation logic is tested with constructed policies. Real records from the lab are for
  verification, not for unit tests.
- **A fix for a wrong verdict needs a test that asserts the wrong branch is not taken**,
  not merely that the right answer appears. Otherwise the regression returns unnoticed.
- New behaviour that changes an existing reading of a policy belongs in `CHANGELOG.md`
  under the current version, and in `docs/policy-context.md` if it adds a reason for `?`.

## House style

- Comments and docstrings explain *why*, not what the line does. A comment restating the
  code is noise, and worth flagging.
- No emoji in code, comments or output.
- Prose in code and documentation is English; discussion on the PR may be German.

## Do not comment on

These are deliberate project decisions, configured in `pyproject.toml`. Comments about
them are noise:

- Line length. `E501` is ignored on purpose; table rows and TUI strings are long.
- One-line guard clauses. `E701` is ignored on purpose.
- The leading-underscore names that are imported across modules. They are internal to the
  project, not private to the file.
