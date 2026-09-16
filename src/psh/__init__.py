"""psh — Physician-Scientist Harness: a governed control plane.

psh is not a bigger agent. It is the control plane a physician-scientist's work runs
through: a trusted kernel that classifies data and enforces where it may travel, a durable
WorkGraph that outlives models and agents, and a composition boundary so specialised
harnesses plug in rather than being merged.

Two defects in the predecessor design motivated it, both demonstrated in code before any of
this was written:

1. A PHI boundary enforced on tool arguments let a chart note reach a model provider
   through the context. Fixed by labelling data rather than call sites, and by treating a
   model call as egress.
2. Citation checking verified that a source existed, not that it supported the sentence.
   Fixed by ``ClaimSupport``.

Quick start::

    from psh import PSHConfig, TrustedKernel, get_profile
    from psh.runtime import Runner

    policy = get_profile("clinical_research").freeze()   # local only, PHI ceiling
    kernel = TrustedKernel(PSHConfig(), policy=policy)
    runner = Runner(kernel, policy=policy)

    result = runner.run("Summarise the HFpEF evidence", sources={"34449189": abstract})
    if result.released_output is None:
        print("refused:", result.error, "| quarantined as", result.quarantine_ref)

The policy is a ceiling: ``Runner`` refuses a per-run policy wider than the kernel's, and
``policy.envelope(risk=...)`` refuses a risk above ``risk_ceiling``.

(The snippet that stood here until v0.5.1 called ``profile.as_config_kwargs()`` and
``as_envelope_kwargs()``, which have raised ``PolicyDenied`` since v0.2 — a quick start that
cannot run is a defect in the same class as the ones this package exists to catch.)
"""

from .config import PSHConfig, default_state_dir
from .policy import PolicySnapshot
from .contracts import (
    ApprovalDenied, ApprovalRequired, ArtifactRef, Autonomy, Budget, BudgetExhausted,
    CapabilityUnavailable, ComponentKind, ComponentManifest, ContextItem,
    ContextProjection, ContractViolation, DelegationContract, EgressDenied, EventEnvelope,
    ModelProfile, PolicyDenied, Principal, PSHError, RiskTier, RunEnvelope,
    VerificationFailed,
)
from .evidence import (
    Certainty, Claim, ClaimSupport, ClaimSupportVerifier, Directness, Evidence,
    EvidenceRecord, Relationship, RetractionStatus, SourceType, VerifiedSpan,
)
from .kernel import (
    AuthorityLattice, ExecutionResult, IngressGateway, ModelCallResult, ModelUsage,
    PersistenceGateway, Quarantine, TrustedKernel, ValidationStatus,
)
from .labels import (
    DataLabel, Declassification, Destination, Labeled, Sensitivity, combine,
    deep_label_of, unwrap_deep,
)
from .profiles import PROFILES, WorkProfile, get_profile, profile_names
from .runtime import DEFAULT_SYSTEM_PROMPT, RunResult, Runner
from .workgraph import EdgeKind, NodeKind, WorkGraph

__version__ = "0.5.1"

__all__ = [
    "TrustedKernel", "PSHConfig", "Runner", "RunResult", "WorkGraph", "NodeKind",
    "EdgeKind", "RunEnvelope", "Budget", "Principal", "RiskTier", "Autonomy",
    "ComponentManifest", "ComponentKind", "ContextItem", "ContextProjection",
    "DelegationContract", "EventEnvelope", "ModelProfile", "ArtifactRef",
    "DataLabel", "Labeled", "Declassification", "Sensitivity", "Destination", "combine",
    "Claim", "Evidence", "ClaimSupport", "ClaimSupportVerifier", "Certainty",
    "Relationship", "Directness",
    "WorkProfile", "PROFILES", "get_profile", "profile_names",
    "PSHError", "PolicyDenied", "EgressDenied", "BudgetExhausted", "ApprovalRequired",
    "ApprovalDenied", "VerificationFailed", "CapabilityUnavailable", "ContractViolation",
    "DEFAULT_SYSTEM_PROMPT", "default_state_dir", "__version__",
    "PolicySnapshot", "AuthorityLattice", "IngressGateway", "PersistenceGateway",
    "Quarantine", "ExecutionResult", "ModelCallResult", "ModelUsage", "ValidationStatus",
    "EvidenceRecord", "VerifiedSpan", "SourceType", "RetractionStatus",
    "deep_label_of", "unwrap_deep",
]
