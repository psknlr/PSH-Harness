"""Budget governor: soft limits warn, hard limits stop.

The review's framing, carried over from the predecessor and extended to delegation: a
budget that only reports consumption is a metric; one that stops the run is a control.
Delegation budgets are strictly nested, so fanning out cannot multiply a ceiling.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..contracts import Budget, BudgetExhausted, RunEnvelope

__all__ = ["BudgetSnapshot", "BudgetGovernor", "BudgetState"]


@dataclass
class BudgetState:
    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    model_calls: int = 0
    tool_calls: int = 0
    delegations: int = 0
    started_at: float = field(default_factory=time.time)
    warned: set = field(default_factory=set)

    @property
    def tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def elapsed(self) -> float:
        return time.time() - self.started_at

    def as_dict(self) -> dict[str, Any]:
        return {"tokens": self.tokens, "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens, "usd": round(self.usd, 4),
                "model_calls": self.model_calls, "tool_calls": self.tool_calls,
                "delegations": self.delegations,
                "elapsed_minutes": round(self.elapsed / 60, 2)}

    def freeze(self) -> "BudgetSnapshot":
        return BudgetSnapshot(
            input_tokens=self.input_tokens, output_tokens=self.output_tokens, usd=self.usd,
            model_calls=self.model_calls, tool_calls=self.tool_calls,
            delegations=self.delegations, started_at=self.started_at,
            warned=frozenset(self.warned))


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    """A read-only view of consumption.

    The governor's live counters were reachable as a public mutable attribute; a caller
    could zero them. Nothing outside the governor now sees the live object — only this
    frozen copy. (Frozen dataclasses are advisory against object.__setattr__, which is the
    documented in-process limit; this closes the ordinary path, not the adversarial one.)
    """

    input_tokens: int
    output_tokens: int
    usd: float
    model_calls: int
    tool_calls: int
    delegations: int
    started_at: float
    warned: frozenset

    @property
    def tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def elapsed(self) -> float:
        return time.time() - self.started_at

    def as_dict(self) -> dict[str, Any]:
        return {"tokens": self.tokens, "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens, "usd": round(self.usd, 4),
                "model_calls": self.model_calls, "tool_calls": self.tool_calls,
                "delegations": self.delegations,
                "elapsed_minutes": round(self.elapsed / 60, 2)}


class BudgetGovernor:
    """Tracks consumption per run and enforces its ceilings."""

    def __init__(self, budget: Budget | None = None, *,
                 on_warning: Callable[[str], None] | None = None,
                 audit: Callable[..., Any] | None = None) -> None:
        self.budget = budget or Budget()
        self._on_warning = on_warning
        self._audit = audit
        self._states: dict[str, BudgetState] = {}

    def _state(self, envelope: RunEnvelope) -> BudgetState:
        """The live, mutable counters for a run. Private: callers get snapshot()."""
        return self._states.setdefault(envelope.run_id, BudgetState())

    def snapshot(self, envelope: RunEnvelope | None = None) -> "BudgetSnapshot":
        """Read-only consumption for one run, or an aggregate over all runs.

        The live BudgetState used to be reachable as ``governor.state(envelope)``, which
        returned the mutable object itself — a caller could zero the counters. Only frozen
        copies leave the governor now.
        """
        if envelope is not None:
            return self._state(envelope).freeze()
        agg = BudgetState()
        for st in self._states.values():
            agg.input_tokens += st.input_tokens
            agg.output_tokens += st.output_tokens
            agg.usd += st.usd
            agg.model_calls += st.model_calls
            agg.tool_calls += st.tool_calls
            agg.delegations += st.delegations
            agg.started_at = min(agg.started_at, st.started_at)
        return agg.freeze()

    def state(self, envelope: RunEnvelope) -> "BudgetSnapshot":
        """Backward-compatible name; returns the frozen snapshot, never the live object."""
        return self.snapshot(envelope)

    def _budget_for(self, envelope: RunEnvelope) -> Budget:
        return envelope.budget or self.budget

    def _warn(self, envelope: RunEnvelope, key: str, message: str) -> None:
        state = self._state(envelope)
        if key in state.warned:
            return
        state.warned.add(key)
        if self._on_warning is not None:
            self._on_warning(message)
        if self._audit is not None:
            self._audit("budget_warning", run_id=envelope.run_id, limit=key)

    # ---------------------------------------------------------------- recording
    def record_model_usage(self, envelope: RunEnvelope, in_tokens: int, out_tokens: int,
                           usd: float = 0.0) -> None:
        state = self._state(envelope)
        state.input_tokens += in_tokens
        state.output_tokens += out_tokens
        state.usd += usd
        self._enforce(envelope)

    # ----------------------------------------------------------------- checking
    def check_model_call(self, envelope: RunEnvelope) -> None:
        budget = self._budget_for(envelope)
        state = self._state(envelope)
        if state.model_calls >= budget.max_model_calls:
            raise BudgetExhausted(
                f"model-call ceiling reached ({budget.max_model_calls}); run stopped")
        state.model_calls += 1
        self._enforce(envelope)

    def check_tool_call(self, envelope: RunEnvelope) -> None:
        budget = self._budget_for(envelope)
        state = self._state(envelope)
        if state.tool_calls >= budget.max_tool_calls:
            raise BudgetExhausted(
                f"tool-call ceiling reached ({budget.max_tool_calls}); run stopped")
        state.tool_calls += 1
        self._enforce(envelope)

    def check_delegation(self, envelope: RunEnvelope) -> None:
        budget = self._budget_for(envelope)
        state = self._state(envelope)
        if state.delegations >= budget.max_delegations:
            raise BudgetExhausted(
                f"delegation ceiling reached ({budget.max_delegations}); run stopped")
        state.delegations += 1

    def _enforce(self, envelope: RunEnvelope) -> None:
        budget = self._budget_for(envelope)
        state = self._state(envelope)
        if state.tokens >= budget.tokens_hard:
            raise BudgetExhausted(
                f"hard token ceiling reached ({state.tokens} >= {budget.tokens_hard}); "
                "run stopped")
        if state.usd >= budget.usd_hard:
            raise BudgetExhausted(
                f"hard cost ceiling reached (${state.usd:.2f} >= ${budget.usd_hard:.2f})")
        if state.elapsed >= budget.seconds_hard:
            raise BudgetExhausted(
                f"hard time ceiling reached ({state.elapsed/60:.1f} min)")
        if envelope.expired:
            raise BudgetExhausted("run deadline passed")
        if state.tokens >= budget.tokens_soft:
            self._warn(envelope, "tokens",
                       f"soft token budget passed ({state.tokens}/{budget.tokens_soft})")
        if state.usd >= budget.usd_soft:
            self._warn(envelope, "usd",
                       f"soft cost budget passed (${state.usd:.2f}/${budget.usd_soft:.2f})")
        if state.elapsed >= budget.seconds_soft:
            self._warn(envelope, "time",
                       f"soft time budget passed ({state.elapsed/60:.0f} min)")

    def remaining(self, envelope: RunEnvelope) -> dict[str, Any]:
        budget = self._budget_for(envelope)
        state = self._state(envelope)
        return {"tokens": max(0, budget.tokens_hard - state.tokens),
                "usd": round(max(0.0, budget.usd_hard - state.usd), 4),
                "minutes": round(max(0.0, budget.seconds_hard - state.elapsed) / 60, 1),
                "model_calls": max(0, budget.max_model_calls - state.model_calls),
                "tool_calls": max(0, budget.max_tool_calls - state.tool_calls)}
