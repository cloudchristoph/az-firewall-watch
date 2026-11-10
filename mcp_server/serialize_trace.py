"""Evaluation traces and rule references as JSON-friendly dicts.

This is the body of what ``serialize.trace_to_dict`` promises, kept in its own
module so the policy tools and the analysis tools never edit the same file.
Everything here is pure: no I/O, no ``textual``.

The trace is shaped like the dialog's tree (passes, collections, rules,
checks) and folded like it by default: collections that were evaluated and
missed collapse into one counted entry, collections after the deciding rule
collapse into a "not evaluated" count, and anything an agent could still be
wrong about (a collection with a rule the local check cannot decide) stays open.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from viewer.azure_resources import FirewallPolicyInfo, IpGroupInfo, Rule
from viewer.trace import (
    MATCH,
    UNKNOWN,
    Check,
    CollectionTrace,
    Flow,
    LoggedMatch,
    PassTrace,
    RuleTrace,
    Trace,
    build_trace,
    first_problem,
    nearest_rules,
    rule_score,
)

VERDICTS = ("allow", "deny", "dnat", "unknown")
NOT_EVALUATED = "not_evaluated"

PASS_TITLES = {"dnat": "DNAT rules", "network": "Network rules", "application": "Application rules"}

# Words the firewall writes into the Action column, and what they decide.
_ALLOW_WORDS = frozenset({"allow"})
_DENY_WORDS = frozenset({"deny", "denywiththreat", "drop"})
_DNAT_WORDS = frozenset({"dnat"})


def rule_ref(*parts: str) -> str:
    """``policy » group » collection » rule``, leaving out parts that are empty."""
    return " » ".join(part for part in parts if part)


# ── flow and checks ──────────────────────────────────────────────────────────

def flow_to_dict(flow: Flow) -> dict[str, Any]:
    """The flow a trace evaluated, with the same names the log rows use."""
    return {
        "category": flow.category or None,
        "protocol": flow.protocol or None,
        "source": flow.src_ip or None,
        "destination": flow.dst_fqdn or flow.dst_ip or None,
        "dst_port": flow.dst_port or None,
        "explicit_proxy": flow.explicit_proxy,
        "tls_inspected": flow.tls_inspected,
    }


@dataclass
class _Render:
    """What the serialisers share: the flow, whether it is hypothetical, and IP group names by id."""

    flow: Flow
    hypothetical: bool = False
    group_names: dict[str, str] = field(default_factory=dict)

    def groups(self, ids: list[str]) -> list[str]:
        # The rule holds resource ids; a group that was not loaded is named by the last id segment.
        return [f"ip-group:{self.group_names.get(gid) or gid.rsplit('/', 1)[-1]}" for gid in ids]


def _observed_expected(name: str, rule: Rule, ctx: _Render) -> tuple[Any, list[str]]:
    """What the flow carries for one criterion and what the rule asks for."""
    flow = ctx.flow
    if name == "source":
        return flow.src_ip or None, [*rule.source_addresses, *ctx.groups(rule.source_ip_groups)]
    if name == "destination":
        expected = [*rule.destination_addresses, *ctx.groups(rule.destination_ip_groups),
                    *rule.destination_fqdns, *(f"fqdn-tag:{t}" for t in rule.fqdn_tags),
                    *(f"web-category:{c}" for c in rule.web_categories), *rule.target_urls]
        return flow.dst_fqdn or flow.dst_ip or None, expected
    if name == "port":
        return flow.dst_port or None, list(rule.destination_ports) or ["any"]
    if name == "protocol":
        return flow.protocol or None, list(rule.protocols) or ["any"]
    return None, []


def _check_to_dict(check: Check, rule: Rule, ctx: _Render) -> dict[str, Any]:
    """One criterion: ``status`` is match, miss, unknown or n/a, with observed against expected."""
    observed, expected = _observed_expected(check.name, rule, ctx)
    return {"criterion": check.name, "status": check.result, "observed": observed, "expected": expected,
            "detail": check.detail}


def _rule_to_dict(rt: RuleTrace, ctx: _Render) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": rt.rule.name,
        "status": rt.verdict,
        "would_match" if ctx.hypothetical else "logged": rt.logged,
        "checks": [_check_to_dict(c, rt.rule, ctx) for c in rt.checks],
    }
    if rt.rule.http_headers:
        # Names only: the values can carry tokens.
        out["inserts_http_headers"] = [h.name for h in rt.rule.http_headers]
    return out


# ── collections and passes ───────────────────────────────────────────────────

def _collection_status(ct: CollectionTrace) -> str:
    return ct.verdict if ct.evaluated else NOT_EVALUATED


def _collection_head(ct: CollectionTrace) -> dict[str, Any]:
    rc = ct.collection
    return {
        "policy": ct.policy_name or None,
        "group": ct.group.name,
        "group_priority": ct.group.priority,
        "collection": rc.name,
        "priority": rc.priority,
        "action": rc.action or None,
        "kind": rc.kind,
        "evaluated": ct.evaluated,
        "status": _collection_status(ct),
        "note": ct.note or None,
    }


def _collection_to_dict(ct: CollectionTrace, ctx: _Render) -> dict[str, Any]:
    out = _collection_head(ct)
    out["rules"] = [_rule_to_dict(r, ctx) for r in ct.rules]
    return out


def _has_unknown(ct: CollectionTrace) -> bool:
    return ct.verdict == UNKNOWN or any(r.verdict == UNKNOWN for r in ct.rules)


def _keep_open(ct: CollectionTrace, highlighted: set[int]) -> bool:
    """Whether a folded view still shows this collection in full."""
    if not ct.evaluated:
        return False
    if any(r.logged for r in ct.rules) or ct.verdict == MATCH:
        return True
    return _has_unknown(ct) or any(id(r) in highlighted for r in ct.rules)


def _pass_result(p: PassTrace) -> str:
    if not p.evaluated:
        return NOT_EVALUATED
    if not p.collections:
        return "none"
    evaluated = [c for c in p.collections if c.evaluated]
    if p.stopped_here:
        return "matched"
    if any(c.verdict == UNKNOWN for c in evaluated):
        return "unknown"
    if any(c.verdict == MATCH for c in evaluated):
        return "computed_match"
    return "no_match"


def _folded_collections(p: PassTrace, highlighted: set[int], ctx: _Render) -> list[dict[str, Any]]:
    """The pass's collections with runs of uninteresting ones collapsed into counts."""
    has_match = any(any(r.logged for r in c.rules) for c in p.collections if c.evaluated)
    items: list[dict[str, Any]] = []
    miss_run = 0
    not_evaluated_run = 0

    def flush() -> None:
        nonlocal miss_run, not_evaluated_run
        if miss_run:
            items.append({"folded": True, "position": "before_match" if has_match else "no_match",
                          "collections": miss_run, "all_miss": True})
        if not_evaluated_run:
            items.append({"folded": True, "position": "after_match", "not_evaluated": not_evaluated_run})
        miss_run = not_evaluated_run = 0

    for ct in p.collections:
        if not ct.evaluated:
            if miss_run:
                flush()
            not_evaluated_run += 1
        elif _keep_open(ct, highlighted):
            flush()
            items.append(_collection_to_dict(ct, ctx))
        else:
            if not_evaluated_run:
                flush()
            miss_run += 1
    flush()
    return items


def _pass_to_dict(p: PassTrace, highlighted: set[int], ctx: _Render, *, full_tree: bool) -> dict[str, Any]:
    if full_tree:
        collections = [_collection_to_dict(c, ctx) for c in p.collections]
    else:
        collections = _folded_collections(p, highlighted, ctx)
    return {
        "kind": p.kind,
        "title": PASS_TITLES.get(p.kind, p.kind),
        "evaluated": p.evaluated,
        "result": _pass_result(p),
        "note": p.note or None,
        "collections_total": len(p.collections),
        "collections": collections,
    }


def _group_names(ip_groups: dict[str, IpGroupInfo] | None) -> dict[str, str]:
    return {gid: grp.name for gid, grp in (ip_groups or {}).items()}


def trace_to_dict(trace: Trace, *, full_tree: bool = False, hypothetical: bool = False,
                  ip_groups: dict[str, IpGroupInfo] | None = None) -> dict[str, Any]:
    """An evaluation trace: passes → collections → rules → checks.

    Folded unless ``full_tree``. ``hypothetical`` marks a trace of a flow that
    was not logged: the rule that decides it is flagged ``would_match`` instead
    of ``logged``, because the firewall never reported it. ``ip_groups`` lets
    the checks name IP groups instead of showing the tail of their ids.
    """
    ctx = _Render(trace.flow, hypothetical, _group_names(ip_groups))
    highlighted = {id(r) for r in nearest_rules(trace)} if trace.matched_rule is None else set()
    return {
        "flow": flow_to_dict(trace.flow),
        "threat_intel": trace.threat_intel,
        "passes": [_pass_to_dict(p, highlighted, ctx, full_tree=full_tree) for p in trace.passes],
        "infrastructure": trace.infrastructure,
        "result": trace.outcome,
        "warnings": list(trace.warnings),
        "folded": not full_tree,
    }


# ── matched rule, nearest misses ─────────────────────────────────────────────

def _owners(trace: Trace) -> dict[int, CollectionTrace]:
    """Rule trace (by identity) → the collection trace it sits in."""
    return {id(r): c for p in trace.passes for c in p.collections for r in c.rules}


def matched_rule_to_dict(trace: Trace) -> dict[str, Any] | None:
    """The rule the evaluation stopped at, with its path, priorities and action; ``None`` without one."""
    rt = trace.matched_rule
    if rt is None:
        return None
    ct = _owners(trace)[id(rt)]
    rc = ct.collection
    return {
        "ref": rule_ref(ct.policy_name, ct.group.name, rc.name, rt.rule.name),
        "policy": ct.policy_name or None,
        "group": ct.group.name,
        "collection": rc.name,
        "rule": rt.rule.name,
        "kind": rc.kind,
        "group_priority": ct.group.priority,
        "collection_priority": rc.priority,
        "action": rc.action or None,
    }


def nearest_misses_to_dict(trace: Trace, limit: int = 3,
                           ip_groups: dict[str, IpGroupInfo] | None = None) -> list[dict[str, Any]]:
    """The rules that came closest without matching, each with the criterion to blame."""
    ctx = _Render(trace.flow, group_names=_group_names(ip_groups))
    owners = _owners(trace)
    out: list[dict[str, Any]] = []
    for rt in nearest_rules(trace, limit):
        ct = owners[id(rt)]
        problem = first_problem(rt)
        out.append({
            "ref": rule_ref(ct.policy_name, ct.group.name, ct.collection.name, rt.rule.name),
            "status": rt.verdict,
            "action": ct.collection.action or None,
            "matching_criteria": rule_score(rt),
            "failing_criterion": _check_to_dict(problem, rt.rule, ctx) if problem is not None else None,
        })
    return out


def unevaluable_rules(trace: Trace, limit: int = 10) -> list[dict[str, Any]]:
    """Rules whose verdict stays ``unknown`` and the criterion that cannot be decided locally."""
    owners = _owners(trace)
    out: list[dict[str, Any]] = []
    for p in trace.passes:
        for ct in p.collections:
            for rt in ct.rules:
                if rt.verdict != UNKNOWN or rt.logged:
                    continue
                problem = first_problem(rt)
                out.append({
                    "ref": rule_ref(owners[id(rt)].policy_name, ct.group.name, ct.collection.name, rt.rule.name),
                    "criterion": problem.name if problem is not None else None,
                    "detail": problem.detail if problem is not None else None,
                })
                if len(out) >= limit:
                    return out
    return out


# ── verdict and sentence ─────────────────────────────────────────────────────

def _word_verdict(word: str | None) -> str:
    low = (word or "").strip().lower()
    if low in _ALLOW_WORDS:
        return "allow"
    if low in _DENY_WORDS:
        return "deny"
    if low in _DNAT_WORDS:
        return "dnat"
    return "unknown"


def _any_unknown(trace: Trace) -> bool:
    return any(r.verdict == UNKNOWN for p in trace.passes if p.evaluated for c in p.collections for r in c.rules)


def verdict(trace: Trace, *, uncertain: bool = False) -> str:
    """``allow``, ``deny``, ``dnat`` or ``unknown``.

    A logged row decides by the action the firewall wrote. A hypothetical flow
    decides by the first rule that would match; ``uncertain`` says a rule that
    cannot be evaluated locally sits before it, so nothing is claimed.
    """
    if uncertain:
        return "unknown"
    logged = _word_verdict(trace.flow.action)
    if trace.flow.threat_intel or logged != "unknown":
        return logged
    rt = trace.matched_rule
    if rt is not None:
        rc = _owners(trace)[id(rt)].collection
        return "dnat" if rc.kind == "dnat" else _word_verdict(rc.action)
    if trace.outcome.startswith("default action"):
        return "unknown" if _any_unknown(trace) else "deny"
    return "unknown"


def _flow_phrase(flow: Flow) -> str:
    target = flow.dst_fqdn or flow.dst_ip or "?"
    if flow.dst_port:
        target = f"{target}:{flow.dst_port}"
    head = f"{flow.protocol} " if flow.protocol else ""
    return f"{head}{flow.src_ip or '?'} to {target}"


def outcome_sentence(trace: Trace, flow: Flow | None = None, *, hypothetical: bool = False,
                     uncertain: bool = False) -> str:
    """One sentence that says what decided the flow, in the dialog's wording."""
    flow = flow or trace.flow
    phrase = _flow_phrase(flow)
    unknown_n = sum(1 for p in trace.passes if p.evaluated for c in p.collections for r in c.rules
                    if r.verdict == UNKNOWN and not r.logged)
    doubt = (f" {unknown_n} rule{'s' if unknown_n != 1 else ''} could not be evaluated locally (service tags, "
             "FQDN tags, web categories or unreadable IP groups)." if unknown_n else "")

    if flow.threat_intel:
        return (f"{phrase}: {trace.outcome}, decided before any rule was evaluated "
                f"(Threat Intelligence {trace.threat_intel}).")
    matched = matched_rule_to_dict(trace)
    if matched is not None:
        action = matched["action"] or "matched"
        if hypothetical:
            tail = (" A rule that cannot be evaluated locally comes earlier, so this is not certain."
                    if uncertain else "")
            return f"{phrase}: first matching rule is {matched['ref']} ({action}).{tail}"
        return f"{phrase}: {action} by {matched['ref']}, the rule the firewall logged.{doubt}"
    if "(rule not in loaded policy)" in trace.outcome:
        return (f"{phrase}: {trace.outcome}. The loaded policy snapshot does not contain the logged rule, so the "
                "evaluation path cannot be shown; refresh the policy context.")
    if hypothetical:
        if uncertain:
            return f"{phrase}: no rule matches with certainty.{doubt} The verdict is unknown."
        return f"{phrase}: no rule matches, so the default action applies: Deny."
    return f"{phrase}: {trace.outcome}.{doubt}"


# ── hypothetical flows ───────────────────────────────────────────────────────

def hypothetical_trace(flow: Flow, policy: FirewallPolicyInfo, ip_groups: dict[str, IpGroupInfo]) -> tuple[Trace, bool]:
    """Trace a flow the firewall never logged.

    ``build_trace`` only stops at a rule the firewall reported, so the first
    rule that would match is found on a plain pass and the trace is built
    again with that rule as the stop. The second value says whether a rule
    that cannot be evaluated locally lies before the stop (or, without a
    match, anywhere), which turns the verdict into ``unknown``.
    """
    plain = build_trace(flow, policy, ip_groups)
    uncertain = False
    first: tuple[CollectionTrace, RuleTrace] | None = None
    for p in plain.passes:
        if not p.evaluated or first is not None:
            continue
        for ct in p.collections:
            for rt in ct.rules:
                if rt.verdict == MATCH:
                    first = (ct, rt)
                    break
                if rt.verdict == UNKNOWN:
                    uncertain = True
            if first is not None:
                break
    if first is None:
        return plain, uncertain
    ct, rt = first
    stop = LoggedMatch(policy=ct.policy_name, group=ct.group.name, collection=ct.collection.name,
                       rule=rt.rule.name, action=ct.collection.action or ct.collection.kind)
    return build_trace(flow, policy, ip_groups, stop), uncertain


__all__ = [
    "VERDICTS", "rule_ref", "flow_to_dict", "trace_to_dict", "matched_rule_to_dict",
    "nearest_misses_to_dict", "unevaluable_rules", "verdict", "outcome_sentence", "hypothetical_trace",
]
