"""v0.5.1: the gates compose, and each one reads the whole input.

A second external review ran the v0.5 code rather than reading it and found a family of
defects one level below the ones v0.5 closed. v0.5 asked "is the control on the executing
path?"; these ask "does the control see everything it is deciding about?":

* a gate that reads ``destinations[0]`` of a tuple with two entries;
* a gate that returns early on "ask a human" and skips the absolute denylist behind it;
* a walker that reports "no paths" when it means "I stopped looking";
* a policy root that a caller can replace with a wider policy;
* a containment check hand-written beside the containment predicate that already exists;
* a ceiling of zero read as "already exceeded";
* a timeout that kills a process but not the process group it created.

Every test here was a reproduction script in that review before it was a test.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from psh import get_profile
from psh.config import PSHConfig
from psh.contracts import (
    Autonomy, Budget, ComponentKind, ComponentManifest, ContractViolation, ModelProfile,
    PolicyDenied, RiskTier, RunEnvelope,
)
from psh.kernel import TrustedKernel
from psh.kernel.authority import UNRESTRICTED
from psh.kernel.isolation import IsolatedRunner
from psh.labels import DataLabel, Destination, Sensitivity
from psh.policy import PolicySnapshot
from psh.runtime import Runner

LOCAL = (Destination.LOCAL_COMPUTE, Destination.LOCAL_MODEL, Destination.USER_OUTPUT)
CN_PHI = "患者张伟，住院号 2023081234，身份证号 110101199003074512，手机 13812345678。"


def kernel_with(policy, tmp_path, **kw):
    return TrustedKernel(PSHConfig(state_dir=tmp_path / policy.profile_id).ensure_dirs(),
                         policy=policy, **kw)


# ------------------------------------- 1. the kernel is the policy root

NARROW = PolicySnapshot(profile_id="narrow", allowed_destinations=LOCAL,
                        autonomy=Autonomy.SUGGEST, risk_ceiling=RiskTier.R1_ROUTINE)
BROAD = PolicySnapshot(profile_id="broad",
                       allowed_destinations=LOCAL + (Destination.PUBLIC_REMOTE,),
                       autonomy=Autonomy.ACT, risk_ceiling=RiskTier.R3_CLINICAL)


def test_a_run_policy_may_not_be_wider_than_the_kernels(tmp_path):
    """The reproduction: a peer_review kernel ran a literature policy and reached a provider.

    ``model_calls=1, refusals=0`` — every gate behaved correctly on an envelope minted under
    a policy the kernel never agreed to.
    """
    k = kernel_with(NARROW, tmp_path)
    remote = ModelProfile(id="frontier", provider="cloud",
                          destination=Destination.PUBLIC_REMOTE,
                          max_label=Sensitivity.PUBLIC)
    reached = []
    result = Runner(k, model=remote,
                    model_invoke=lambda p: reached.append(p) or "leaked").run(
        "say hello", policy=BROAD)
    assert reached == [], "the run reached a provider the kernel forbids"
    assert result.status == "refused" and result.released_output is None
    assert "PUBLIC_REMOTE" in result.error or "destinations" in result.error
    assert k.broker.model_calls == 0
    k.close()


def test_a_wider_policy_is_refused_at_runner_construction_too(tmp_path):
    k = kernel_with(NARROW, tmp_path)
    with pytest.raises(PolicyDenied, match="grants authority"):
        Runner(k, policy=BROAD)
    k.close()


def test_a_narrower_run_policy_is_accepted(tmp_path):
    k = kernel_with(BROAD, tmp_path)
    runner = Runner(k, policy=NARROW)
    assert runner.policy.profile_id == "narrow"
    k.close()


def test_clamping_is_available_but_never_the_default(tmp_path):
    k = kernel_with(NARROW, tmp_path)
    runner = Runner(k, policy=BROAD, clamp_policy=True)
    assert Destination.PUBLIC_REMOTE not in runner.policy.allowed_destinations
    assert runner.policy.autonomy is Autonomy.SUGGEST
    k.close()


@pytest.mark.parametrize("widening", [
    {"autonomy": Autonomy.ACT},
    {"require_isolated_tools": False},
    {"require_claim_support": False},
    {"budget": Budget(usd_hard=999.0)},
    {"declassifiers": ("anyone",)},
    {"declassify_floor": Sensitivity.PUBLIC},
    {"approval_required_at": RiskTier.R4_KERNEL},
])
def test_policy_with_refuses_every_kind_of_widening(widening):
    """``with_()`` validated three fields while its docstring promised containment."""
    base = PolicySnapshot(profile_id="base", autonomy=Autonomy.SUGGEST,
                          require_isolated_tools=True, require_claim_support=True,
                          declassifiers=("deid",), declassify_floor=Sensitivity.SENSITIVE,
                          approval_required_at=RiskTier.R2_CONSEQUENTIAL,
                          budget=Budget(usd_hard=1.0))
    with pytest.raises(PolicyDenied):
        base.with_(**widening)


def test_policy_meet_is_contained_by_both_inputs():
    met = BROAD.meet(NARROW)
    assert met.violations_against(BROAD) == []
    assert met.violations_against(NARROW) == []


def test_every_policy_field_is_either_an_authority_dimension_or_documented_metadata():
    """A field added to PolicySnapshot without a containment decision fails here."""
    from dataclasses import fields

    metadata = {"profile_id", "profile_version", "notes", "verification_model_id"}
    checked = {"max_data_label", "allowed_destinations", "risk_ceiling", "autonomy",
               "require_citation", "require_claim_support", "require_isolated_tools",
               "approval_required_at", "declassifiers", "declassify_floor", "deadline",
               "budget"}
    declared = {f.name for f in fields(PolicySnapshot)}
    assert declared == metadata | checked, (
        f"unclassified policy fields: {sorted(declared - metadata - checked)}")


# --------------------------- 2. a gate reads every destination it is given

class _MixedTool:
    """Declares a local destination first and a public one second."""

    @property
    def manifest(self):
        return ComponentManifest(
            id="mixed", name="mixed", kind=ComponentKind.TOOL, max_label=Sensitivity.PHI,
            requires_network=True,
            destinations=(Destination.LOCAL_COMPUTE, Destination.PUBLIC_REMOTE))

    def invoke(self, payload, envelope):  # pragma: no cover - must never run
        raise AssertionError("the gate should have refused this call")


def test_phi_may_not_reach_a_tool_whose_second_destination_is_public(tmp_path):
    wide = PolicySnapshot(profile_id="wide", autonomy=Autonomy.ACT,
                          allowed_destinations=LOCAL + (Destination.PUBLIC_REMOTE,))
    k = kernel_with(wide, tmp_path)
    decision = k.tool_gateway.check(k.classify("Patient Alice Cheng, MRN 04851923"),
                                    _MixedTool().manifest, k.envelope())
    assert not decision.allowed
    assert "PUBLIC_REMOTE" in decision.reason
    assert Destination.PUBLIC_REMOTE in decision.destinations
    k.close()


def test_a_destination_the_run_forbids_is_refused_even_when_it_is_not_the_first(tmp_path):
    k = kernel_with(PolicySnapshot(profile_id="localonly", autonomy=Autonomy.ACT,
                                   allowed_destinations=LOCAL), tmp_path)
    decision = k.tool_gateway.check(k.classify({"q": "public question"}),
                                    _MixedTool().manifest, k.envelope())
    assert not decision.allowed and "PUBLIC_REMOTE" in decision.reason
    k.close()


def test_the_approval_record_names_every_destination(tmp_path):
    records = []
    wide = PolicySnapshot(profile_id="wide2", autonomy=Autonomy.ACT)
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "ap").ensure_dirs(), policy=wide,
                      approval_handler=lambda what, record: records.append(record) or True)

    class Writer:
        @property
        def manifest(self):
            return ComponentManifest(
                id="writer", name="writer", kind=ComponentKind.TOOL, mutates=True,
                human_approval=True, max_label=Sensitivity.PHI,
                destinations=(Destination.LOCAL_COMPUTE, Destination.PERSISTENT))

        def invoke(self, payload, envelope):
            return {"ok": True}

    k.broker.call_tool(Writer(), k.classify({"q": "x"}), k.envelope())
    assert records and "PERSISTENT" in records[0]["targets"], records[0]["targets"]
    k.close()


# ------------------- 3. an approval prompt is a question, not a verdict

class _PhiWriter:
    """A filesystem tool with a PHI ceiling, so path tests are not about labels."""

    def __init__(self):
        self.ran: list = []

    @property
    def manifest(self):
        return ComponentManifest(id="phi_writer", name="phi writer",
                                 kind=ComponentKind.TOOL, max_label=Sensitivity.PHI,
                                 mutates=True, requires_filesystem=True,
                                 destinations=(Destination.LOCAL_COMPUTE,))

    def invoke(self, payload, envelope):
        self.ran.append(payload)
        return {"written": True}


class _Shell:
    def __init__(self):
        self.ran = []

    @property
    def manifest(self):
        return ComponentManifest(id="shell", name="shell", kind=ComponentKind.TOOL,
                                 max_label=Sensitivity.INTERNAL, mutates=True,
                                 requires_filesystem=True,
                                 destinations=(Destination.LOCAL_COMPUTE,))

    def invoke(self, payload, envelope):
        self.ran.append(payload)
        return {"stdout": "ok"}


def test_a_prompted_command_is_still_checked_against_the_absolute_denylist(tmp_path):
    """``git push --force`` is documented as refused regardless of autonomy."""
    k = kernel_with(PolicySnapshot(profile_id="promptbench", autonomy=Autonomy.ACT),
                    tmp_path, approval_handler=lambda what, record: True)
    decision = k.tool_gateway.check(k.classify({"command": "git push --force origin main"}),
                                    _Shell().manifest, k.envelope())
    assert not decision.allowed and "denied command pattern" in decision.reason
    k.close()


def test_a_prompted_command_is_still_checked_against_the_allowed_paths(tmp_path):
    allowed = tmp_path / "ok"
    allowed.mkdir()
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "pp").ensure_dirs(),
                      policy=PolicySnapshot(profile_id="pp", autonomy=Autonomy.ACT),
                      approval_handler=lambda what, record: True,
                      allowed_paths=[str(allowed / "*")])
    decision = k.tool_gateway.check(
        k.classify({"command": "git commit -am x", "path": "/etc/passwd"}),
        _Shell().manifest, k.envelope())
    assert not decision.allowed and "outside the allowed paths" in decision.reason
    k.close()


def test_a_prompted_command_that_passes_everything_still_asks(tmp_path):
    allowed = tmp_path / "ok2"
    allowed.mkdir()
    asked = []
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "pq").ensure_dirs(),
                      policy=PolicySnapshot(profile_id="pq", autonomy=Autonomy.ACT),
                      approval_handler=lambda what, record: asked.append(what) or True,
                      allowed_paths=[str(allowed / "*")])
    shell = _Shell()
    k.broker.call_tool(shell, k.classify({"command": "git push origin main"}), k.envelope())
    assert asked and shell.ran, "the command should run once a human approves"
    k.close()


# ------------------------------- 4. an unverifiable payload is refused

def test_a_path_buried_below_the_walk_limit_is_refused_not_ignored(tmp_path):
    from psh import EgressDenied

    allowed = tmp_path / "ok3"
    allowed.mkdir()
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "deep").ensure_dirs(),
                      policy=PolicySnapshot(profile_id="deep", autonomy=Autonomy.ACT),
                      allowed_paths=[str(allowed / "*")])
    payload = {"target": "/outside/secret"}
    for _ in range(12):                      # bury it below the walker's depth limit
        payload = {"nest": payload}
    with pytest.raises(EgressDenied, match="too deeply nested"):
        k.broker.call_tool(_PhiWriter(), k.classify(payload), k.envelope())
    k.close()


def test_a_shallow_payload_is_still_verified_normally(tmp_path):
    allowed = tmp_path / "ok4"
    allowed.mkdir()
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "shallow").ensure_dirs(),
                      policy=PolicySnapshot(profile_id="shallow", autonomy=Autonomy.ACT),
                      allowed_paths=[str(allowed / "*")])
    writer = _PhiWriter()
    k.broker.call_tool(writer, k.classify({"config": {"target": str(allowed / "f.txt")}}),
                       k.envelope())
    assert len(writer.ran) == 1
    k.close()


# ----------------------- 5. delegation uses the one authority predicate

def test_delegation_refuses_a_child_that_widens_anything_but_the_four_old_fields():
    """The reviewer's case: same destinations, label and tokens; everything else wider."""
    from psh.contracts import DelegationContract
    from psh.kernel.egress import DelegationGateway

    parent = RunEnvelope(
        risk=RiskTier.R1_ROUTINE, autonomy=Autonomy.SUGGEST,
        allowed_capabilities=("safe",), denied_capabilities=("blocked",),
        budget=Budget(tokens_hard=1000, usd_hard=1.0, seconds_hard=10,
                      max_model_calls=1, max_tool_calls=1, max_delegations=1))
    child = RunEnvelope(
        risk=RiskTier.R4_KERNEL, autonomy=Autonomy.ACT,
        allowed_destinations=parent.allowed_destinations,
        allowed_capabilities=UNRESTRICTED, denied_capabilities=(),
        budget=Budget(tokens_hard=1000, usd_hard=999.0, seconds_hard=999,
                      max_model_calls=999, max_tool_calls=999, max_delegations=999))
    decision = DelegationGateway().check(
        DelegationContract(task_id="t", objective="anything", envelope=child), parent)
    assert not decision.allowed
    for dimension in ("risk", "autonomy", "capabilities", "budget.usd_hard"):
        assert dimension in decision.reason, decision.reason


# ------------------------------------- 6. a ceiling of zero is not "exceeded"

def test_a_zero_cost_budget_permits_a_run_that_spends_nothing(tmp_path):
    """``peer_review`` sets usd_hard=0.0 to mean "local models only"."""
    policy = get_profile("peer_review").freeze()
    assert policy.budget.usd_hard == 0.0
    k = kernel_with(policy, tmp_path)
    local = ModelProfile(id="local-8b", provider="local",
                         destination=Destination.LOCAL_MODEL, max_label=Sensitivity.PHI,
                         usd_per_1k_input=0.0, usd_per_1k_output=0.0)
    result = Runner(k, model=local, model_invoke=lambda p: "a local answer",
                    policy=policy).run("Summarise the reviewer comments")
    assert result.status == "ok", result.error
    k.close()


def test_spending_above_a_zero_ceiling_still_stops_the_run(tmp_path):
    from psh.contracts import BudgetExhausted

    policy = PolicySnapshot(profile_id="nocost", autonomy=Autonomy.ACT,
                            allowed_destinations=LOCAL + (Destination.PUBLIC_REMOTE,),
                            budget=Budget(usd_hard=0.0, usd_soft=0.0))
    k = kernel_with(policy, tmp_path)
    paid = ModelProfile(id="paid", provider="cloud", destination=Destination.PUBLIC_REMOTE,
                        max_label=Sensitivity.PHI, usd_per_1k_input=1.0,
                        usd_per_1k_output=1.0)
    with pytest.raises(BudgetExhausted, match="cost ceiling"):
        for _ in range(3):
            k.broker.call_model(k.classify("hello " * 500, origin="public_source"), paid,
                                k.envelope(), invoke=lambda p: "reply " * 500)
    k.close()


# ------------------------- 7. a profile that forbids persistence writes nothing

def test_a_peer_review_run_writes_nothing_to_the_workgraph(tmp_path):
    import sqlite3

    policy = get_profile("peer_review").freeze()
    state = tmp_path / "pr"
    k = TrustedKernel(PSHConfig(state_dir=state).ensure_dirs(), policy=policy)
    result = Runner(k, policy=policy).run(
        "Reviewer note: the primary endpoint in this manuscript is unblinded")
    assert result.status == "ok"
    k.close()
    rows = sqlite3.connect(state / "index.db").execute("SELECT title, body FROM nodes").fetchall()
    assert rows == [], f"a run under a no-PERSISTENT profile wrote {rows}"


def test_the_persistence_gateway_refuses_a_write_the_run_may_not_make(tmp_path):
    from psh.workgraph import NodeKind

    policy = get_profile("peer_review").freeze()
    k = kernel_with(policy, tmp_path)
    with pytest.raises(PolicyDenied, match="PERSISTENT"):
        k.persistence.commit_node(kind=NodeKind.TASK, title="a manuscript title",
                                  principal="local", source_run="r1",
                                  envelope=k.envelope())
    k.close()


def test_an_ordinary_profile_still_persists(tmp_path):
    policy = get_profile("literature").freeze()
    k = kernel_with(policy, tmp_path)
    result = Runner(k, policy=policy).run("What is known about HFpEF?")
    assert result.node_ids.get("task"), "a persisting profile must still bind its task"
    k.close()


# ------------------------------- 8. the run policy reaches the output gate

def test_require_claim_support_comes_from_the_run_policy(tmp_path):
    """v0.5 forwarded require_citation and left claim support on the kernel's setting."""
    from psh.contracts import VerificationFailed

    lenient = PolicySnapshot(profile_id="lenient", require_claim_support=False)
    strict = PolicySnapshot(profile_id="strict", require_claim_support=True)
    k = kernel_with(lenient, tmp_path)
    assert k.output_gate.require_support is False
    output = k.ingress.ensure("Empagliflozin reduced mortality by 40%.",
                              origin="model_output")
    with pytest.raises(VerificationFailed):
        k.output_gate.check(output, k.envelope(), require_support=True,
                            require_citation=strict.require_citation)
    k.close()


# --------------------------------- 9. isolation boundaries hold at the edges

def test_a_component_id_may_not_be_a_path(tmp_path):
    with pytest.raises(ValueError, match="must match"):
        ComponentManifest(id="../../escaped", name="x", kind=ComponentKind.TOOL,
                          backend="subprocess", entrypoint="/bin/true")


def test_the_executor_refuses_a_workdir_outside_the_sandbox_root(tmp_path):
    """Second layer: a manifest-like object that did not come through the constructor."""
    from psh.kernel.isolation import IsolatedExecutor

    class Sneaky:
        id = "../../escaped"
        entrypoint = f"{sys.executable} -c pass"
        timeout_s = 5.0
        memory_mb = 256
        destinations = ()
        allowed_hosts = ()
        requires_secrets = ()

    executor = IsolatedExecutor(IsolatedRunner(), workdir_root=tmp_path / "sandbox")
    workdir = executor._workdir_for(Sneaky(), RunEnvelope())
    assert (tmp_path / "sandbox").resolve() in workdir.parents


def test_a_timeout_kills_the_whole_process_group(tmp_path):
    """A grandchild that outlives "timeout and was killed" makes the message false."""
    marker = tmp_path / "grandchild.txt"
    parent = tmp_path / "parent.py"
    parent.write_text(
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', \"import time; time.sleep(1.2);"
        f" open({str(marker)!r}, 'w').write('alive')\"])\n"
        "time.sleep(10)\n")
    result = IsolatedRunner().run([sys.executable, str(parent)], workdir=tmp_path / "w",
                                  timeout_s=0.7)
    assert result.timed_out
    time.sleep(2.0)
    assert not marker.exists(), "a descendant survived the timeout and kept working"


def test_a_component_that_does_not_speak_the_protocol_is_a_contract_violation(tmp_path):
    script = tmp_path / "prose.py"
    script.write_text("print('I am not JSON')\n")
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "pv").ensure_dirs(),
                      policy=PolicySnapshot(profile_id="pv", autonomy=Autonomy.ACT))

    class Tool:
        @property
        def manifest(self):
            return ComponentManifest(id="prose", name="prose", kind=ComponentKind.TOOL,
                                     backend="subprocess",
                                     entrypoint=f"{sys.executable} {script}",
                                     max_label=Sensitivity.PHI,
                                     destinations=(Destination.LOCAL_COMPUTE,))

        def invoke(self, payload, envelope):  # pragma: no cover
            raise AssertionError

    with pytest.raises(ContractViolation, match="one JSON value"):
        k.broker.call_tool(Tool(), k.classify({"q": "x"}), k.envelope())
    k.close()


def test_allowed_hosts_may_be_a_generator(tmp_path):
    """``bool(list(allowed_hosts))`` after the list was already consumed is always False."""
    result = IsolatedRunner().run(
        [sys.executable, "-c", "import os; print(os.environ['HTTP_PROXY'])"],
        workdir=tmp_path / "gen", allowed_hosts=(h for h in ["127.0.0.1:1"]),
        allow_private_hosts=True, timeout_s=30)
    assert result.stdout.strip().startswith("http://127.0.0.1")


# ---------------------------------- 10. manifest contract fields are enforced

def test_a_network_component_must_name_a_remote_destination():
    with pytest.raises(ValueError, match="requires_network"):
        ComponentManifest(id="net", name="net", kind=ComponentKind.TOOL,
                          requires_network=True, destinations=())


def test_min_autonomy_is_enforced_by_compatible_with():
    manifest = ComponentManifest(id="actor", name="actor", kind=ComponentKind.TOOL,
                                 min_autonomy=Autonomy.ACT)
    assert not manifest.compatible_with(RunEnvelope(autonomy=Autonomy.OBSERVE))[0]
    assert not manifest.compatible_with(RunEnvelope(autonomy=Autonomy.SUGGEST))[0]
    assert manifest.compatible_with(RunEnvelope(autonomy=Autonomy.ACT))[0]


def test_clinical_research_actually_requires_isolated_tools(tmp_path):
    policy = get_profile("clinical_research").freeze()
    assert policy.require_isolated_tools is True
    k = kernel_with(policy, tmp_path)

    class InProcess:
        @property
        def manifest(self):
            return ComponentManifest(id="local", name="local", kind=ComponentKind.TOOL,
                                     max_label=Sensitivity.PHI,
                                     destinations=(Destination.LOCAL_COMPUTE,))

        def invoke(self, payload, envelope):  # pragma: no cover
            raise AssertionError("an in-process tool must not run under this profile")

    with pytest.raises(PolicyDenied, match="process-isolated"):
        k.broker.call_tool(InProcess(), k.classify({"q": "x"}), k.envelope())
    k.close()


def test_the_isolation_requirement_rides_on_the_envelope(tmp_path):
    """So a run policy stricter than the kernel's still gets its requirement enforced."""
    k = kernel_with(PolicySnapshot(profile_id="loose", autonomy=Autonomy.ACT), tmp_path)
    assert k.broker.require_isolation is False
    strict = k.envelope(require_isolated_tools=True)
    assert strict.require_isolated_tools

    class InProcess:
        @property
        def manifest(self):
            return ComponentManifest(id="local2", name="local2", kind=ComponentKind.TOOL,
                                     max_label=Sensitivity.PHI,
                                     destinations=(Destination.LOCAL_COMPUTE,))

        def invoke(self, payload, envelope):  # pragma: no cover
            raise AssertionError

    with pytest.raises(PolicyDenied, match="process-isolated"):
        k.broker.call_tool(InProcess(), k.classify({"q": "x"}), strict)
    k.close()


# --------------------------------------- 11. the loop detector detects loops

def test_repeating_a_request_across_independent_runs_is_not_a_loop(tmp_path):
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "loop").ensure_dirs())
    runner = Runner(k)
    assert [runner.run("the same harmless question").status for _ in range(4)] == ["ok"] * 4
    k.close()


def test_repeating_a_request_within_one_task_is_a_loop(tmp_path):
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "loop2").ensure_dirs())
    runner = Runner(k)
    statuses = [runner.run("the same question", task_id="task-1").status for _ in range(4)]
    assert statuses[:2] == ["ok", "ok"] and statuses[2] == "refused"
    k.close()


# -------------------------------------------- 12. Chinese text is not invisible

def test_distinct_chinese_memories_are_not_deduplicated_into_one():
    from psh.context import ContextCompiler
    from psh.contracts import ContextItem

    texts = ["心力衰竭患者需要评估射血分数", "糖尿病患者需要评估肾功能", "高血压患者需要监测血压"]
    compiler = ContextCompiler()
    projection = compiler.compile(
        items=[ContextItem(kind="memory", content=t) for t in texts],
        envelope=RunEnvelope(), token_budget=8000, query="评估")
    assert compiler.last_trace.after_dedup == 3
    assert len(projection.items) == 3


def test_a_chinese_claim_can_be_supported_by_its_chinese_source():
    from psh.evidence import ClaimSupportVerifier

    support = ClaimSupportVerifier().verify(
        statement="该药物显著降低心力衰竭患者的全因死亡率", identifier="34449189",
        source_text="在这项随机对照试验中，该药物显著降低了心力衰竭患者的全因死亡率（风险比 0.80）。")
    assert support.supports, support.rationale


def test_chinese_identifiers_are_classified_as_phi(tmp_path):
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "cn").ensure_dirs())
    label = k.classify(CN_PHI).label
    assert label.sensitivity is Sensitivity.PHI, label
    assert not label.permits(Destination.PUBLIC_REMOTE)
    k.close()


def test_ordinary_chinese_clinical_prose_is_not_flagged_as_phi(tmp_path):
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "cn2").ensure_dirs())
    for text in ("患者需要评估射血分数，建议完善超声心动图。",
                 "该研究纳入 200 名心力衰竭患者，平均年龄 68 岁。"):
        assert k.classify(text).label.sensitivity is not Sensitivity.PHI, text
    k.close()


def test_a_chinese_query_still_ranks_capabilities_semantically():
    from psh.capabilities import CapabilityRegistry

    registry = CapabilityRegistry()
    for ident, description in (("echo", "心电图与射血分数分析"), ("genomics", "基因组变异注释")):
        registry.register(_stub_component(ident, description))
    candidates = registry.resolve("射血分数评估", RunEnvelope(), limit=2)
    assert candidates and candidates[0].manifest.id == "echo"


def _stub_component(ident: str, description: str):
    class Stub:
        @property
        def manifest(self):
            return ComponentManifest(id=ident, name=ident, kind=ComponentKind.TOOL,
                                     description=description,
                                     destinations=(Destination.LOCAL_COMPUTE,))

        def invoke(self, payload, envelope):
            return {}

    return Stub()


# ------------------------------------------- 13. lifecycle and documentation

def test_the_runner_does_not_open_a_second_connection_to_the_index(tmp_path):
    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "conn").ensure_dirs())
    assert Runner(k).graph is k.graph
    k.close()


def test_runner_stages_match_the_stages_a_run_emits(tmp_path):
    from psh.runtime.runner import STAGES

    k = TrustedKernel(PSHConfig(state_dir=tmp_path / "stages").ensure_dirs())
    result = Runner(k).run("hello")
    assert Runner.STAGES == STAGES
    assert [s.stage for s in result.stages] == list(STAGES)
    k.close()


def test_quarantined_content_is_readable_without_the_in_memory_index(tmp_path):
    from psh.kernel.release import Quarantine

    q = Quarantine(tmp_path / "q")
    ref = q.hold("refused output", label=DataLabel(Sensitivity.INTERNAL))
    fresh = Quarantine(tmp_path / "q")          # as after a restart
    assert fresh.release(ref) == "refused output"


def test_the_package_version_matches_the_distribution():
    import tomllib

    import psh

    root = Path(__file__).resolve().parents[1]
    declared = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    assert psh.__version__ == declared


def test_the_quick_start_in_the_package_docstring_uses_live_api():
    """The snippet must not call the two methods that have raised since v0.2."""
    import psh

    doc = psh.__doc__ or ""
    snippet = doc[doc.index("Quick start"):doc.index("(The snippet")]
    assert "as_config_kwargs()" not in snippet and "as_envelope_kwargs()" not in snippet
    assert "freeze()" in snippet


def test_config_fields_are_either_consumed_or_listed_as_pending():
    """A settings field that does nothing must say so rather than look load-bearing."""
    import re
    from dataclasses import fields

    root = Path(__file__).resolve().parents[1] / "src" / "psh"
    sources = "\n".join(f.read_text(encoding="utf-8") for f in root.rglob("*.py")
                        if f.name != "config.py")
    for spec in fields(PSHConfig):
        if spec.name in PSHConfig.PENDING_FIELDS:
            assert not re.search(rf"\.{spec.name}\b", sources), (
                f"{spec.name} is listed as pending but is now used; remove it from "
                "PSHConfig.PENDING_FIELDS")
        elif spec.name not in ("state_dir", "profile", "policy_version", "budget",
                               "default_risk", "require_claim_support",
                               "destination_ceilings"):
            assert re.search(rf"\.{spec.name}\b", sources), f"{spec.name} is read nowhere"
