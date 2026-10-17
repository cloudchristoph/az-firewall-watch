"""The policy context: firewall, policy and IP groups from ARM, cached like the TUI.

States:

* ``off``: switched off (``--no-policy-context`` / ``POLICY_CONTEXT=off``); no ARM access at all.
* ``waiting_for_firewall_id``: on, but no firewall known yet; the first log record names it.
* ``loading``: the first fetch (or cache read) is running.
* ``loaded``: a snapshot is available. A failed refresh keeps the old snapshot
  and says so in ``reason``, like the TUI keeps the previous context on screen.
* ``unavailable``: the fetch failed and there is nothing to show; ``reason`` says why.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from viewer import management
from viewer.cache import CachedSnapshot

from .buffer import BufferedRow

log = logging.getLogger(__name__)

Loader = Callable[..., Awaitable[CachedSnapshot | None]]

# An unknown rule in the log means the cached policy is older than the rule.
# One refresh fixes that; more than one per minute would only hammer ARM while
# a rule is being rolled out.
AUTO_REFRESH_MIN_AGE_S = 60.0
AUTO_REFRESH_INTERVAL_S = 60.0

OFF_REASON = "Policy context is switched off (--no-policy-context or POLICY_CONTEXT=off)."
WAITING_REASON = "No firewall known yet: the context loads when the first log record arrives (or set AZFW_FIREWALL_ID)."


class ContextHolder:
    """Owns the snapshot and every fetch of it; tools only read."""

    def __init__(self, *, enabled: bool, firewall_id: str | None = None, loader: Loader | None = None,
                 auto_refresh_min_age: float = AUTO_REFRESH_MIN_AGE_S,
                 auto_refresh_interval: float = AUTO_REFRESH_INTERVAL_S) -> None:
        self.enabled = enabled
        self.firewall_id: str | None = firewall_id
        self._loader = loader
        self.auto_refresh_min_age = auto_refresh_min_age
        self.auto_refresh_interval = auto_refresh_interval
        self.snapshot: CachedSnapshot | None = None
        self.reason: str | None = None
        self.last_attempt_at: float | None = None
        self._loading = False
        self._known_rules: set[tuple[str, str, str]] = set()
        self._last_auto_refresh: float | None = None     # monotonic; None, not 0.0 (young machines)
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[Any] | None = None

    # ── state ────────────────────────────────────────────────────────────────
    @property
    def state(self) -> str:
        if not self.enabled:
            return "off"
        if self.snapshot is not None:
            return "loaded"
        if self._loading:
            return "loading"
        if self.firewall_id is None:
            return "waiting_for_firewall_id"
        if self.last_attempt_at is None:
            return "loading"   # an id is known and the first load is about to start
        return "unavailable"

    @property
    def loaded(self) -> bool:
        return self.snapshot is not None

    @property
    def age_s(self) -> float | None:
        return self.snapshot.age_seconds() if self.snapshot is not None else None

    @property
    def known_rules(self) -> frozenset[tuple[str, str, str]]:
        """``(group, collection, rule)`` names of the loaded policy chain."""
        return frozenset(self._known_rules)

    def status(self) -> dict[str, Any]:
        from .serialize import iso_utc

        state = self.state
        reason = self.reason
        if state == "off":
            reason = OFF_REASON
        elif state == "waiting_for_firewall_id":
            reason = WAITING_REASON
        age = self.age_s
        return {
            "state": state,
            "age_s": round(age, 1) if age is not None else None,
            "fetched_at": iso_utc(self.snapshot.fetched_at) if self.snapshot is not None else None,
            "reason": reason,
            "refreshing": self._loading and self.snapshot is not None,
        }

    def unavailable_answer(self) -> dict[str, Any]:
        """The answer tools give instead of data while no snapshot is loaded."""
        state = self.state
        hints = {
            "off": "Restart the server without --no-policy-context (or set POLICY_CONTEXT=on).",
            "waiting_for_firewall_id": "Wait for the first log record, or start the server with --firewall-id.",
            "loading": "The context is loading; ask again in a few seconds.",
            "unavailable": "Check that the identity has Reader on the firewall, its policy and IP groups, "
                           "then call refresh_policy_context.",
        }
        status = self.status()
        return {"available": False, "state": state, "reason": status["reason"] or "The policy context is not loaded.",
                "hint": hints.get(state, "")}

    # ── loading ──────────────────────────────────────────────────────────────
    def start(self) -> None:
        """Begin loading when a firewall id is already configured."""
        if self.enabled and self.firewall_id is not None and self.snapshot is None:
            self._schedule(force=False)

    def set_firewall_id(self, firewall_id: str) -> None:
        """The stream saw its first firewall record. Only the first id counts, as in the TUI."""
        if self.firewall_id is not None:
            return
        self.firewall_id = firewall_id
        if self.enabled:
            self._schedule(force=False)

    def _schedule(self, *, force: bool) -> asyncio.Task[Any] | None:
        if self._task is not None and not self._task.done():
            return self._task
        try:
            self._task = asyncio.get_running_loop().create_task(self.refresh(force=force), name="azfw-policy-context")
        except RuntimeError:   # no running loop: the caller loads explicitly later
            return None
        return self._task

    async def refresh(self, force: bool = True) -> dict[str, Any]:
        """Load (``force``: bypass and rewrite the shared cache) and return :meth:`status`."""
        if not self.enabled or self.firewall_id is None:
            return self.status()
        async with self._lock:
            self._loading = True
            errors: list[str] = []
            try:
                loader = self._loader or management.load_management_data
                snap = await loader(self.firewall_id, force=force, errors=errors)
            except asyncio.CancelledError:
                raise
            except Exception as exc:   # a loader bug must not kill the server
                log.exception("Policy context load failed")
                snap, errors = None, [str(exc) or type(exc).__name__]
            finally:
                self._loading = False
            # Not in ``finally``: a load cancelled at shutdown is no failed attempt.
            self.last_attempt_at = time.time()
            if snap is None:
                why = errors[0] if errors else "no ARM access"
                if self.snapshot is not None:
                    self.reason = f"Refresh failed, the previous snapshot stays in use: {why}"
                else:
                    self.reason = why
                log.warning("Policy context unavailable: %s", why)
            else:
                self.snapshot = snap
                self.reason = None
                self._known_rules = {
                    (g.name, rc.name, r.name)
                    for _, g in (snap.policy.all_groups() if snap.policy else [])
                    for rc in g.rule_collections for r in rc.rules
                }
                log.info("Policy context loaded for %s", snap.firewall.name or self.firewall_id)
        return self.status()

    # ── keeping it current ───────────────────────────────────────────────────
    def note_rows(self, rows: Iterable[BufferedRow]) -> bool:
        """Check a batch for rules the loaded policy does not know; refresh once if one shows up."""
        if not self._known_rules:
            return False
        for item in rows:
            r = item.row
            if r.rule_name and r.rule_collection_group and \
                    (r.rule_collection_group, r.rule_collection, r.rule_name) not in self._known_rules:
                return self.note_unknown_rule(r.rule_name)
        return False

    def note_unknown_rule(self, rule_name: str = "") -> bool:
        """A logged rule is missing from the snapshot: refresh, at most once per interval.

        Only when the snapshot is older than a minute: a snapshot that young
        already reflects what ARM knows, and the rule is not readable yet.
        """
        if not self.enabled or self.snapshot is None or self.firewall_id is None:
            return False
        if self.snapshot.age_seconds() < self.auto_refresh_min_age:
            return False
        now = time.monotonic()
        if self._last_auto_refresh is not None and now - self._last_auto_refresh < self.auto_refresh_interval:
            return False
        self._last_auto_refresh = now
        log.info("Refreshing the policy context: the log names an unknown rule %r", rule_name)
        return self._schedule(force=True) is not None

    def check_cache_age(self) -> bool:
        """Re-fetch once the snapshot's TTL is over (the TUI checks every minute)."""
        if self.snapshot is None or self.snapshot.is_fresh() or not self.enabled:
            return False
        return self._schedule(force=True) is not None

    async def wait_idle(self) -> None:
        """Wait for a scheduled load to finish (tests, and the lifespan's shutdown)."""
        task = self._task
        if task is not None and not task.done():
            await asyncio.gather(task, return_exceptions=True)

    async def aclose(self) -> None:
        task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


__all__ = ["ContextHolder", "AUTO_REFRESH_MIN_AGE_S", "AUTO_REFRESH_INTERVAL_S"]
