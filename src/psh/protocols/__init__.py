"""Protocol boundaries: HarnessAdapter for harness-to-harness composition.

MCP (capability discovery against tools and services) and A2A (agent-to-agent
interoperability) are named in the review as the other two protocol boundaries. They are
NOT implemented here — see the report's boundaries section. HarnessAdapter is the one this
build needed, because composing the existing sable harness was a stated requirement.
"""

from .harness_adapter import (
    EvidenceBundle, ExecutionPlan, HarnessAdapter, HarnessManifest, HealthReport,
    ProvenanceCapsule, RunHandle, RunStatus,
)
from .sable_adapter import SABLE_AVAILABLE, SableAdapter

__all__ = [
    "HarnessAdapter", "HarnessManifest", "ExecutionPlan", "RunHandle", "RunStatus",
    "EvidenceBundle", "ProvenanceCapsule", "HealthReport",
    "SableAdapter", "SABLE_AVAILABLE",
]
