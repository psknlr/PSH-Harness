"""Property-based testing of authority monotonicity.

A reviewer's finding was that ``restrict()`` enforced four dimensions and silently permitted
escalation on five others. That is the characteristic failure of example-based testing on a
lattice: each test covers the dimension its author was thinking about, and the uncovered
ones look fine because nothing exercises them.

So the guarantee is stated as a property over generated envelope pairs rather than as a
list of cases. Adding a dimension to ``AuthorityLattice.BUDGET_DIMENSIONS`` brings it under
these tests automatically, which is the point: the next dimension should not depend on
someone remembering to write its test.
"""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from psh.contracts import Autonomy, Budget, PolicyDenied, RiskTier, RunEnvelope  # noqa: E402
from psh.kernel.authority import AuthorityLattice  # noqa: E402
from psh.labels import DataLabel, Destination, Sensitivity  # noqa: E402

SETTINGS = settings(max_examples=250, deadline=None,
                    suppress_health_check=[HealthCheck.too_slow])

_DESTINATIONS = list(Destination)
_SENSITIVITIES = list(Sensitivity)


@st.composite
def budgets(draw):
    return Budget(
        tokens_soft=draw(st.integers(1, 10_000)),
        tokens_hard=draw(st.integers(1, 100_000)),
        usd_soft=draw(st.floats(0.01, 10.0, allow_nan=False)),
        usd_hard=draw(st.floats(0.01, 100.0, allow_nan=False)),
        seconds_soft=draw(st.floats(1.0, 600.0, allow_nan=False)),
        seconds_hard=draw(st.floats(1.0, 3600.0, allow_nan=False)),
        max_model_calls=draw(st.integers(1, 100)),
        max_tool_calls=draw(st.integers(1, 100)),
        max_delegations=draw(st.integers(0, 10)))


@st.composite
def envelopes(draw):
    return RunEnvelope(
        risk=draw(st.sampled_from(list(RiskTier))),
        autonomy=draw(st.sampled_from(list(Autonomy))),
        max_label=DataLabel(draw(st.sampled_from(_SENSITIVITIES))),
        allowed_destinations=frozenset(draw(st.lists(
            st.sampled_from(_DESTINATIONS), min_size=1, max_size=6, unique=True))),
        allowed_capabilities=tuple(draw(st.lists(
            st.sampled_from(["a", "b", "c", "d"]), max_size=4, unique=True))),
        denied_capabilities=tuple(draw(st.lists(
            st.sampled_from(["x", "y"]), max_size=2, unique=True))),
        deadline=draw(st.one_of(st.none(), st.floats(1.0, 1e6, allow_nan=False))),
        budget=draw(budgets()))


@given(envelopes())
@SETTINGS
def test_reflexive(envelope):
    """An envelope always contains itself. A lattice failing this is unusable."""
    assert AuthorityLattice.is_subset(envelope, envelope)


@given(envelopes())
@SETTINGS
def test_transitive(root):
    """A delegation chain cannot accumulate authority.

    Constructed rather than filtered: random triples almost never form a chain, so
    ``assume`` would discard nearly every example and prove nothing. Building the chain with
    ``meet`` exercises the same property on inputs that actually reach the assertion.
    """
    middle = AuthorityLattice.meet(root.restrict(risk=RiskTier.R0_TRIVIAL), root)
    leaf = AuthorityLattice.meet(middle.restrict(autonomy=Autonomy.OBSERVE), middle)
    assert AuthorityLattice.is_subset(middle, root)
    assert AuthorityLattice.is_subset(leaf, middle)
    assert AuthorityLattice.is_subset(leaf, root), "authority leaked across a two-hop chain"


@given(envelopes())
@SETTINGS
def test_antisymmetric_on_authority(envelope):
    """Mutual containment means identical authority on every dimension.

    Tested against a re-derived copy: an envelope clamped to itself must be mutually
    contained with the original, and therefore equal on every governed dimension.
    """
    clone = AuthorityLattice.meet(envelope, envelope)
    assert AuthorityLattice.is_subset(clone, envelope)
    assert AuthorityLattice.is_subset(envelope, clone)
    assert clone.max_label.sensitivity == envelope.max_label.sensitivity
    assert clone.allowed_destinations == envelope.allowed_destinations
    assert clone.risk == envelope.risk and clone.autonomy == envelope.autonomy
    for dimension in AuthorityLattice.BUDGET_DIMENSIONS:
        assert getattr(clone.budget, dimension) == getattr(envelope.budget, dimension)


@given(parent=envelopes(), child_kwargs=st.lists(
    st.sampled_from(["risk", "autonomy", "deadline", "budget", "max_label",
                     "allowed_destinations"]),
    min_size=1, max_size=3, unique=True))
@SETTINGS
def test_restrict_never_widens(parent, child_kwargs):
    """The central property: no argument combination yields authority the parent lacks.

    Values are drawn adversarially — deliberately maximal — so a dimension the lattice
    forgot would surface as a child holding more than its parent.
    """
    widest = {
        "risk": RiskTier.R4_KERNEL,
        "autonomy": Autonomy.ACT,
        "deadline": 1e12,
        "budget": Budget(tokens_soft=10 ** 9, tokens_hard=10 ** 9, usd_soft=1e6,
                         usd_hard=1e6, seconds_soft=1e9, seconds_hard=1e9,
                         max_model_calls=10 ** 6, max_tool_calls=10 ** 6,
                         max_delegations=10 ** 6),
        "max_label": DataLabel(Sensitivity.SECRET),
        "allowed_destinations": frozenset(_DESTINATIONS),
    }
    kwargs = {key: widest[key] for key in child_kwargs}
    try:
        child = parent.restrict(**kwargs)
    except PolicyDenied:
        return  # refusing to widen is the correct outcome
    assert AuthorityLattice.is_subset(child, parent), (
        f"restrict({sorted(kwargs)}) produced a child exceeding its parent: "
        f"{AuthorityLattice.violations(child, parent)}")


@given(envelopes())
@SETTINGS
def test_narrowing_always_succeeds(parent):
    """Restricting to the bottom of every dimension must never be refused.

    The dual of the widening property. A lattice that rejected a strictly narrower child
    would push callers toward constructing envelopes directly, which is how authority checks
    get bypassed in practice.
    """
    child = parent.restrict(
        risk=RiskTier.R0_TRIVIAL, autonomy=Autonomy.OBSERVE,
        max_label=DataLabel(Sensitivity.PUBLIC),
        allowed_destinations=frozenset(),
        budget=Budget(tokens_soft=1, tokens_hard=1, usd_soft=0.0, usd_hard=0.0,
                      seconds_soft=0.0, seconds_hard=0.0, max_model_calls=0,
                      max_tool_calls=0, max_delegations=0),
        deadline=parent.deadline if parent.deadline is not None else 1.0)
    assert AuthorityLattice.is_subset(child, parent)


@given(envelopes(), envelopes())
@SETTINGS
def test_meet_is_a_lower_bound_of_both(requested, parent):
    """``meet`` clamps rather than refuses, and its result is contained by the parent."""
    clamped = AuthorityLattice.meet(requested, parent)
    assert AuthorityLattice.is_subset(clamped, parent), \
        AuthorityLattice.violations(clamped, parent)


@given(envelopes())
@SETTINGS
def test_delegation_contract_cannot_exceed_its_parent_run(parent):
    """Delegation uses the same predicate, so it inherits the same guarantee."""
    from psh.contracts import DelegationContract

    # A contract asking for the widest possible authority on every dimension.
    widest = RunEnvelope(
        risk=RiskTier.R4_KERNEL, autonomy=Autonomy.ACT,
        max_label=DataLabel(Sensitivity.SECRET),
        allowed_destinations=frozenset(_DESTINATIONS),
        budget=Budget(tokens_soft=10 ** 9, tokens_hard=10 ** 9, usd_soft=1e6, usd_hard=1e6,
                      seconds_soft=1e9, seconds_hard=1e9, max_model_calls=10 ** 6,
                      max_tool_calls=10 ** 6, max_delegations=10 ** 6))
    contract = DelegationContract(
        task_id="t1", objective="anything", envelope=widest)

    from psh.kernel.egress import DelegationGateway

    decision = DelegationGateway().check(contract, parent)
    if decision.allowed:
        assert AuthorityLattice.is_subset(contract.envelope, parent), \
            "a delegation the gateway allowed granted authority the parent lacks"
    else:
        assert not AuthorityLattice.is_subset(contract.envelope, parent)
