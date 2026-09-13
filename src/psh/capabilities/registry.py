"""Hierarchical capability retrieval.

The review's two-level lazy loading: a domain harness contributes ONE manifest to the
top-level registry, and its internal capabilities are retrieved only after a task has been
routed into that domain. A harness exposing thousands of capabilities therefore costs one
manifest of context rather than thousands of entries — the difference between a registry
that scales and one that poisons every prompt.

Selection is multi-factor, as the review specifies. Embedding similarity alone ranks an
unavailable, policy-incompatible, historically-failing capability alongside a working one;
the score here combines semantic relevance with policy compatibility, recorded success
rate, cost and latency. Policy compatibility is a *filter*, not a weight: an incompatible
capability is excluded rather than ranked low, because a cheap capability that is not
permitted is not a candidate at any price.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from ..contracts import (
    CapabilityUnavailable, ComponentKind, ComponentManifest, ContextItem, RunEnvelope,
)

__all__ = ["CapabilityRegistry", "Candidate", "ResolutionTrace"]


@dataclass(frozen=True, slots=True)
class Candidate:
    """A ranked capability plus the reasoning behind its score."""

    manifest: ComponentManifest
    score: float
    relevance: float
    reason: str

    @property
    def id(self) -> str:
        return self.manifest.id


@dataclass
class ResolutionTrace:
    """What resolution considered and why things were excluded."""

    considered: int = 0
    policy_excluded: int = 0
    domain_narrowed_to: tuple[str, ...] = ()
    returned: int = 0
    exclusions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"considered": self.considered, "policy_excluded": self.policy_excluded,
                "domain_narrowed_to": list(self.domain_narrowed_to),
                "returned": self.returned}


_WORD = re.compile(r"[a-z][a-z0-9-]{2,}")
_STOP = frozenset("""the and for with from that this into over under able all any are
was were will can could would should has have had its their there which who what when
how why not use using used get set run make new via per etc""".split())


def _terms(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if w not in _STOP}


class CapabilityRegistry:
    """Two-level registry: domain harnesses first, then their capabilities.

    Components registered without a ``domain`` are top-level and always eligible. A
    component registered *under* a harness id is invisible to level-1 retrieval and is only
    reachable once that harness has been selected.
    """

    def __init__(self) -> None:
        self._top: dict[str, ComponentManifest] = {}
        self._nested: dict[str, dict[str, ComponentManifest]] = {}
        self._components: dict[str, Any] = {}
        self._success: dict[str, tuple[int, int]] = {}
        self.last_trace = ResolutionTrace()

    # -------------------------------------------------------------- registration
    def register(self, component: Any, *, under: str | None = None) -> ComponentManifest:
        """Register a component. ``under`` places it inside a domain harness."""
        manifest = component.manifest if hasattr(component, "manifest") else component
        if not isinstance(manifest, ComponentManifest):
            raise TypeError("register() needs a Component or a ComponentManifest")
        if under:
            if under not in self._top:
                raise CapabilityUnavailable(
                    f"cannot nest under {under!r}: no such harness is registered")
            self._nested.setdefault(under, {})[manifest.id] = manifest
        else:
            self._top[manifest.id] = manifest
        if hasattr(component, "invoke"):
            self._components[manifest.id] = component
        return manifest

    def component(self, capability_id: str) -> Any:
        try:
            return self._components[capability_id]
        except KeyError:
            raise CapabilityUnavailable(
                f"{capability_id!r} is registered as a manifest but has no invocable "
                "component in this process") from None

    def record_outcome(self, capability_id: str, ok: bool) -> None:
        """Record a success or failure, feeding the historical-success factor."""
        successes, attempts = self._success.get(capability_id, (0, 0))
        self._success[capability_id] = (successes + (1 if ok else 0), attempts + 1)

    def observed_success(self, manifest: ComponentManifest) -> float:
        """Blend observed outcomes with the manifest's declared rate.

        With few observations the declared rate dominates; as evidence accumulates the
        observed rate takes over. Without this, one early failure would permanently sink a
        capability, and one lucky success would promote an unreliable one.
        """
        successes, attempts = self._success.get(manifest.id, (0, 0))
        if attempts == 0:
            return manifest.success_rate
        prior_weight = 3.0
        return ((manifest.success_rate * prior_weight + successes)
                / (prior_weight + attempts))

    # ------------------------------------------------------------------ retrieval
    def resolve_domains(self, query: str, envelope: RunEnvelope, *,
                        limit: int = 3) -> list[Candidate]:
        """Level 1: pick the domain harnesses worth descending into."""
        harnesses = [m for m in self._top.values() if m.kind is ComponentKind.HARNESS]
        return self._rank(harnesses, query, envelope, limit=limit)

    def resolve(self, query: str, envelope: RunEnvelope, *, limit: int = 8,
                domain_limit: int = 3, include_nested: bool = True) -> list[Candidate]:
        """Full two-level retrieval: domains, then capabilities within them.

        Non-harness top-level components compete directly, so a plain local tool does not
        need a harness wrapper to be findable.
        """
        trace = ResolutionTrace()
        pool: list[ComponentManifest] = [
            m for m in self._top.values() if m.kind is not ComponentKind.HARNESS]

        if include_nested:
            domains = self.resolve_domains(query, envelope, limit=domain_limit)
            trace.domain_narrowed_to = tuple(d.id for d in domains)
            for domain in domains:
                pool.extend(self._nested.get(domain.id, {}).values())

        trace.considered = len(pool)
        ranked = self._rank(pool, query, envelope, limit=limit, trace=trace)
        trace.returned = len(ranked)
        self.last_trace = trace
        return ranked

    def _rank(self, pool: Sequence[ComponentManifest], query: str, envelope: RunEnvelope,
              *, limit: int, trace: ResolutionTrace | None = None) -> list[Candidate]:
        query_terms = _terms(query)
        exclusions: list[str] = []
        out: list[Candidate] = []

        for manifest in pool:
            ok, why = manifest.compatible_with(envelope)
            if not ok:
                exclusions.append(f"{manifest.id}: {why}")
                if trace is not None:
                    trace.policy_excluded += 1
                continue

            haystack = _terms(" ".join((
                manifest.name, manifest.description, manifest.domain,
                " ".join(manifest.intents), " ".join(manifest.tags))))
            relevance = (len(query_terms & haystack) / max(1, len(query_terms))
                         if query_terms else 0.5)
            # Intent match is a stronger signal than incidental word overlap.
            if any(intent.lower() in query.lower() for intent in manifest.intents):
                relevance = min(1.0, relevance + 0.35)

            success = self.observed_success(manifest)
            cost_penalty = min(0.25, manifest.expected_usd / 4.0)
            latency_penalty = min(0.2, manifest.expected_latency_s / 120.0)
            score = relevance * 0.6 + success * 0.3 - cost_penalty - latency_penalty
            reason = (f"relevance {relevance:.2f}, success {success:.2f}, "
                      f"~${manifest.expected_usd:.3f}, ~{manifest.expected_latency_s:.1f}s")
            out.append(Candidate(manifest=manifest, score=round(score, 4),
                                 relevance=round(relevance, 4), reason=reason))

        if trace is not None:
            trace.exclusions = tuple(exclusions[:10])
        out.sort(key=lambda c: c.score, reverse=True)
        return out[:limit]

    # ------------------------------------------------------------------ context
    def manifest_items(self, candidates: Sequence[Candidate]) -> list[ContextItem]:
        """Render candidates as context items — summaries only, never full schemas.

        This is the progressive-disclosure half of lazy loading: the model sees enough to
        choose, and the full input schema is supplied only when a capability is invoked.
        """
        items: list[ContextItem] = []
        for candidate in candidates:
            m = candidate.manifest
            items.append(ContextItem(
                kind="manifest", source_ref=m.id, score=candidate.score,
                content=(f"{m.id} ({m.kind.value}): {m.description or m.name}"
                         + (f" [intents: {', '.join(m.intents)}]" if m.intents else "")
                         + (f" [approval required]" if m.human_approval else ""))))
        return items

    def stats(self) -> dict[str, Any]:
        nested_total = sum(len(v) for v in self._nested.values())
        return {"top_level": len(self._top),
                "harnesses": sum(1 for m in self._top.values()
                                 if m.kind is ComponentKind.HARNESS),
                "nested_capabilities": nested_total,
                "nested_by_harness": {k: len(v) for k, v in self._nested.items()},
                "invocable": len(self._components),
                "with_outcome_history": len(self._success)}
