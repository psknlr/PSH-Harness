"""PolicySnapshot: one frozen policy object, so declared policy is effective policy.

A reviewer found two related defects in v0.1's profile plumbing. The first was a plain bug:
the documented usage ``runner.run(request, **profile.as_envelope_kwargs())`` raised
``TypeError`` because ``max_label`` was not a parameter of ``run``. The second was worse and
is the reason this module replaces the mechanism rather than adding the missing parameter:

    literature profile declares  require_citation = True
    as_config_kwargs()           does not carry it
    OutputGate ends up with      require_citation = False

The profile claimed literature work must cite; the kernel did not enforce it. That is the
general failure mode of splitting one policy across several keyword paths — every split is
an opportunity for a field to be declared in one place and dropped in another.

So policy travels as a single immutable object from profile to runner to kernel to gate. A
field that exists on the snapshot reaches every enforcement point, or the snapshot fails to
construct. There is no partial path.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, ClassVar, Mapping, Sequence

from .contracts import Autonomy, Budget, PolicyDenied, RiskTier, RunEnvelope
from .labels import DataLabel, Destination, Sensitivity

__all__ = ["PolicySnapshot"]


#: Autonomy from most to least permissive; a lower index is strictly more authority. Kept
#: identical to ``AuthorityLattice``'s ordering — imported lazily there to avoid a cycle.
_AUTONOMY_ORDER: tuple[Autonomy, ...] = (
    Autonomy.ACT, Autonomy.ACT_WITH_APPROVAL, Autonomy.SUGGEST, Autonomy.OBSERVE)


def _autonomy_rank(value: Autonomy) -> int:
    return _AUTONOMY_ORDER.index(value)


def _earlier(a: float | None, b: float | None) -> float | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _replace_budget(a: Budget, b: Budget, dimensions: Sequence[str]) -> Budget:
    return replace(a, **{d: min(getattr(a, d), getattr(b, d)) for d in dimensions})


def _as_label(value: Any) -> DataLabel | None:
    """Accept either a ``Sensitivity`` or an already-built ``DataLabel``.

    Callers mint envelopes with both shapes, and silently ignoring one of them is how a
    requested ceiling goes unchecked.
    """
    if value is None:
        return None
    return value if isinstance(value, DataLabel) else DataLabel(value)


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """The complete, frozen policy for one run.

    Frozen because a run's policy must not change under it. A component that could widen the
    policy it operates under is not governed by it — the same argument that keeps the kernel
    out of the component system.
    """

    profile_id: str
    profile_version: str = "1"
    max_data_label: Sensitivity = Sensitivity.PHI
    allowed_destinations: tuple[Destination, ...] = (
        Destination.LOCAL_COMPUTE, Destination.LOCAL_MODEL, Destination.USER_OUTPUT,
        Destination.PERSISTENT)
    require_citation: bool = False
    require_claim_support: bool = True
    #: When True the broker refuses any component that is not process-isolated. A profile
    #: that touches identifiable data should set it: a tool running inside the kernel
    #: process is governed by convention, not by the operating system.
    require_isolated_tools: bool = False
    autonomy: Autonomy = Autonomy.ACT_WITH_APPROVAL
    risk_ceiling: RiskTier = RiskTier.R1_ROUTINE
    budget: Budget = field(default_factory=Budget)
    deadline: float | None = None
    approval_required_at: RiskTier = RiskTier.R3_CLINICAL
    verification_model_id: str = ""
    #: Principals permitted to lower a label. Empty by default: declassification is the ONE
    #: operation in the lattice that moves data toward wider exposure, so it is closed unless
    #: a profile opens it by name. My own audit found the Declassification type carried a
    #: principal field that nothing ever checked — a record of who did it, with no control
    #: over who may.
    declassifiers: tuple[str, ...] = ()
    #: The lowest sensitivity a permitted declassifier may reach. PHI -> RESEARCH_DEIDENTIFIED
    #: is the ordinary clinical case; PHI -> PUBLIC is not something a profile should grant
    #: without saying so.
    declassify_floor: Sensitivity = Sensitivity.RESEARCH_DEIDENTIFIED
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.profile_id:
            raise ValueError("a policy snapshot must name the profile it came from")
        if self.require_citation and not self.require_claim_support:
            # Requiring a citation while not checking whether it supports the claim is the
            # exact failure the previous version shipped: a citation that exists and does
            # not support the sentence. Refuse the combination rather than implement it.
            raise PolicyDenied(
                "require_citation without require_claim_support would enforce the presence "
                "of an identifier while never checking that it supports the claim")

    @property
    def permits_network(self) -> bool:
        return any(d in (Destination.PUBLIC_REMOTE, Destination.TRUSTED_REMOTE)
                   for d in self.allowed_destinations)

    def ceiling(self) -> RunEnvelope:
        """The maximum authority this policy grants. Nothing minted may exceed it."""
        return RunEnvelope(
            risk=self.risk_ceiling, autonomy=self.autonomy,
            max_label=DataLabel(self.max_data_label),
            allowed_destinations=frozenset(self.allowed_destinations),
            budget=self.budget, deadline=self.deadline, profile=self.profile_id,
            require_isolated_tools=self.require_isolated_tools)

    def envelope(self, *, clamp: bool = False, **kw: Any) -> RunEnvelope:
        """Mint a ``RunEnvelope`` under this policy. The single construction path.

        The policy is a **ceiling, not a set of defaults**. v0.4 read the requested risk and
        autonomy with ``kw.pop(field, self.field)``, so a caller who passed nothing got the
        policy's value and a caller who passed something got whatever they asked for —
        including ``risk=R4_KERNEL`` under an ``R2`` policy and ``autonomy=ACT`` under a
        ``SUGGEST`` profile. A ceiling that applies only when the caller declines to state a
        value is not a ceiling.

        So every requested dimension is checked against the ceiling by the one predicate
        that already defines authority containment, ``AuthorityLattice``:

            effective = policy ∩ requested

        Widening raises ``PolicyDenied``. Passing ``clamp=True`` asks for the meet instead —
        the request is narrowed to what the policy permits rather than refused, which is the
        right behaviour where a broad default profile is applied to an already narrow run,
        and the wrong behaviour where a caller states an authority it must not have. Refusal
        is the default for that reason.
        """
        from .kernel.authority import AuthorityLattice

        ceiling = self.ceiling()
        # ``or`` is not usable for defaulting here: RiskTier.R0_TRIVIAL is 0 and therefore
        # falsy, so ``kw.pop("risk", None) or self.risk_ceiling`` would silently promote the
        # lowest risk tier to the policy ceiling — the reverse of the bug being fixed.
        def _requested(name: str, fallback: Any) -> Any:
            value = kw.pop(name, None)
            return fallback if value is None else value

        requested = RunEnvelope(
            task_id=kw.pop("task_id", ""), project_id=kw.pop("project_id", ""),
            principal=_requested("principal", ceiling.principal),
            risk=_requested("risk", self.risk_ceiling),
            autonomy=_requested("autonomy", self.autonomy),
            max_label=_as_label(kw.pop("max_label", None)) or DataLabel(self.max_data_label),
            allowed_destinations=frozenset(
                _requested("allowed_destinations", self.allowed_destinations)),
            budget=_requested("budget", self.budget),
            deadline=kw.pop("deadline", self.deadline),
            # Requirements travel on the envelope so a gate reached from anywhere sees the
            # run's own policy rather than whatever the kernel was configured with.
            require_isolated_tools=(self.require_isolated_tools
                                    or bool(kw.pop("require_isolated_tools", False))),
            profile=self.profile_id, **kw)

        if clamp:
            return AuthorityLattice.meet(requested, ceiling)
        violations = AuthorityLattice.violations(requested, ceiling)
        if violations:
            raise PolicyDenied(
                f"policy {self.profile_id!r} is a ceiling and the requested envelope exceeds "
                f"the authority it grants: " + "; ".join(str(v) for v in violations))
        return requested

    #: Budget fields a narrower policy may not raise. Named rather than reflected so that
    #: adding a Budget field is a deliberate decision here, as in ``AuthorityLattice``.
    BUDGET_DIMENSIONS: ClassVar[tuple[str, ...]] = (
        "tokens_soft", "tokens_hard", "usd_soft", "usd_hard", "seconds_soft",
        "seconds_hard", "max_model_calls", "max_tool_calls", "max_delegations")

    def violations_against(self, parent: "PolicySnapshot") -> list[str]:
        """Every dimension on which this policy grants more than ``parent``.

        ``with_()`` validated three fields — data ceiling, destinations, risk — while its
        docstring said "widening is refused". Everything else was free: ``SUGGEST -> ACT``,
        ``require_isolated_tools True -> False``, ``usd_hard 1 -> 999``, a longer deadline,
        a wider declassifier list. A containment check that covers a third of the policy is
        not a containment check, and the omissions were exactly the fields a caller would
        want to relax.

        Every field of the snapshot is now classified as an authority dimension (checked
        here) or as descriptive metadata (``profile_id``, ``profile_version``, ``notes``,
        ``verification_model_id``). There is no third category, so a field added to this
        dataclass without a decision here shows up in ``test_every_policy_field_is_classified``.
        """
        out: list[str] = []
        if self.max_data_label > parent.max_data_label:
            out.append(f"max_data_label: {parent.max_data_label.name} -> "
                       f"{self.max_data_label.name}")
        extra = set(self.allowed_destinations) - set(parent.allowed_destinations)
        if extra:
            out.append(f"destinations: adds {sorted(d.name for d in extra)}")
        if self.risk_ceiling > parent.risk_ceiling:
            out.append(f"risk_ceiling: {parent.risk_ceiling.name} -> "
                       f"{self.risk_ceiling.name}")
        if _autonomy_rank(self.autonomy) < _autonomy_rank(parent.autonomy):
            out.append(f"autonomy: {parent.autonomy.value} -> {self.autonomy.value}")
        # A requirement that is ON in the parent may not be switched OFF by a child: each
        # of these three makes the policy stricter when True.
        for field_name in ("require_citation", "require_claim_support",
                           "require_isolated_tools"):
            if getattr(parent, field_name) and not getattr(self, field_name):
                out.append(f"{field_name}: True -> False")
        # A HIGHER approval threshold means FEWER operations need a human.
        if self.approval_required_at > parent.approval_required_at:
            out.append(f"approval_required_at: {parent.approval_required_at.name} -> "
                       f"{self.approval_required_at.name}")
        new_declassifiers = set(self.declassifiers) - set(parent.declassifiers)
        if new_declassifiers:
            out.append(f"declassifiers: adds {sorted(new_declassifiers)}")
        if self.declassify_floor < parent.declassify_floor:
            out.append(f"declassify_floor: {parent.declassify_floor.name} -> "
                       f"{self.declassify_floor.name}")
        if parent.deadline is not None and (self.deadline is None
                                            or self.deadline > parent.deadline):
            out.append(f"deadline: {parent.deadline} -> {self.deadline}")
        for dimension in self.BUDGET_DIMENSIONS:
            mine, theirs = getattr(self.budget, dimension), getattr(parent.budget, dimension)
            if mine > theirs:
                out.append(f"budget.{dimension}: {theirs} -> {mine}")
        return out

    def is_narrower_than(self, parent: "PolicySnapshot") -> bool:
        """True when this policy grants no authority ``parent`` lacks."""
        return not self.violations_against(parent)

    def enforce_within(self, parent: "PolicySnapshot", *, operation: str) -> "PolicySnapshot":
        """Return self if contained by ``parent``, else raise naming every dimension."""
        violations = self.violations_against(parent)
        if violations:
            raise PolicyDenied(
                f"{operation}: policy {self.profile_id!r} grants authority that "
                f"{parent.profile_id!r} does not — " + "; ".join(violations))
        return self

    def meet(self, other: "PolicySnapshot") -> "PolicySnapshot":
        """The greatest lower bound of two policies: every dimension at its stricter value.

        Used where clamping is kinder than refusing — applying a broad per-run policy under
        a narrow kernel policy, for instance. The result is contained by both inputs, which
        is the property ``test_meet_is_contained_by_both_inputs`` checks.
        """
        return replace(
            self,
            profile_id=f"{self.profile_id}∩{other.profile_id}",
            max_data_label=min(self.max_data_label, other.max_data_label),
            allowed_destinations=tuple(d for d in self.allowed_destinations
                                       if d in set(other.allowed_destinations)),
            require_citation=self.require_citation or other.require_citation,
            require_claim_support=self.require_claim_support or other.require_claim_support,
            require_isolated_tools=(self.require_isolated_tools
                                    or other.require_isolated_tools),
            autonomy=(self.autonomy if _autonomy_rank(self.autonomy)
                      >= _autonomy_rank(other.autonomy) else other.autonomy),
            risk_ceiling=min(self.risk_ceiling, other.risk_ceiling),
            budget=_replace_budget(self.budget, other.budget, self.BUDGET_DIMENSIONS),
            deadline=_earlier(self.deadline, other.deadline),
            approval_required_at=min(self.approval_required_at, other.approval_required_at),
            declassifiers=tuple(d for d in self.declassifiers
                                if d in set(other.declassifiers)),
            declassify_floor=max(self.declassify_floor, other.declassify_floor),
            notes=tuple(dict.fromkeys(self.notes + other.notes)))

    def with_(self, **kw: Any) -> "PolicySnapshot":
        """Return a narrowed copy. Widening is refused, on every dimension."""
        candidate = replace(self, **kw)
        return candidate.enforce_within(self, operation="with_()")

    def summary(self) -> str:
        net = "network" if self.permits_network else "local only"
        return (f"{self.profile_id} v{self.profile_version}: {self.max_data_label.name}, "
                f"{net}, autonomy={self.autonomy.value}, risk<={self.risk_ceiling.name}, "
                f"citation={self.require_citation}, support={self.require_claim_support}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id, "profile_version": self.profile_version,
            "max_data_label": self.max_data_label.name,
            "allowed_destinations": [d.name for d in self.allowed_destinations],
            "require_citation": self.require_citation,
            "require_claim_support": self.require_claim_support,
            "require_isolated_tools": self.require_isolated_tools,
            "autonomy": self.autonomy.value, "risk_ceiling": self.risk_ceiling.name,
            "tokens_hard": self.budget.tokens_hard, "usd_hard": self.budget.usd_hard,
            "deadline": self.deadline}
