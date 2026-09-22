"""Deterministic taint propagation.

CORE PRINCIPLE:
  Reading untrusted information is not itself a violation.
  Using untrusted information as authority for a consequential action can be.

TRUST RULES:
  - Untrusted source -> derived content -> memory does NOT become trusted.
  - Adversary-controlled content taints everything derived from it.
  - Trust propagates pessimistically (take worst trust among all ancestors).
  - Sensitivity propagates pessimistically (take worst sensitivity).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.core.provenance import Sensitivity, TrustLevel, least_trusted, most_sensitive

from context.builder import NormalizedContext
from context.normalizer import squash
from provenance.graph import ProvenanceGraph

_UNTRUSTED = frozenset({
    TrustLevel.UNTRUSTED_INTERNAL,
    TrustLevel.UNTRUSTED_EXTERNAL,
    TrustLevel.ADVERSARY_CONTROLLED,
})

_ADVERSARY = frozenset({TrustLevel.ADVERSARY_CONTROLLED})
_SENSITIVE = frozenset({Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED})


@dataclass
class TaintResult:
    """Summary of taint analysis for the current action."""

    # Does the effective action depend on untrusted content?
    action_depends_on_untrusted: bool
    # Does it depend on adversary-controlled content?
    action_depends_on_adversary: bool
    # Does it carry content that originated from a sensitive source?
    action_has_sensitive_source: bool

    # Text from untrusted provenance (for overlap detection)
    untrusted_texts: list[str] = field(default_factory=list)
    # Text from sensitive provenance
    sensitive_texts: list[str] = field(default_factory=list)
    # Text from adversary-controlled provenance
    adversary_texts: list[str] = field(default_factory=list)

    # Worst (least trusted) level seen across all conversation sources
    worst_trust_level: TrustLevel = TrustLevel.AUTHENTICATED_USER
    # Worst (most sensitive) level seen
    worst_sensitivity: Sensitivity = Sensitivity.PUBLIC


def propagate_taint(ctx: NormalizedContext, graph: ProvenanceGraph) -> TaintResult:
    """Compute taint for the candidate action from the provenance graph and context.

    Uses the graph for structural analysis and the conversation for text collection.
    Memory does not upgrade trust — untrusted content copied to memory stays untrusted.
    """
    untrusted_texts: list[str] = []
    sensitive_texts: list[str] = []
    adversary_texts: list[str] = []
    trust_levels: list[TrustLevel] = []
    sensitivity_levels: list[Sensitivity] = []

    # Graph-derived labels also preserve observed trust laundering through
    # agent output / memory rather than trusting a new record's label alone.
    items = [(f"conv:{i}", item.content) for i, item in enumerate(ctx.conversation)]
    if ctx.observation is not None:
        items.append(("obs:0", ctx.observation.content))
    for node_id, content in items:
        trust = graph.source_trust_level(node_id)
        sensitivity = graph.source_sensitivity(node_id)
        trust_levels.append(trust)
        sensitivity_levels.append(sensitivity)
        if trust in _UNTRUSTED:
            untrusted_texts.append(content)
        if trust in _ADVERSARY:
            adversary_texts.append(content)
        if sensitivity in _SENSITIVE:
            sensitive_texts.append(content)

    worst_trust = least_trusted(trust_levels)
    worst_sens = most_sensitive(sensitivity_levels)

    # Structural graph query for the action node
    action_depends_untrusted = graph.depends_on_untrusted("action:0")
    action_depends_adversary = graph.depends_on_adversary("action:0")
    action_has_sensitive = graph.has_sensitive_source("action:0")

    # Also check history_digest least_trusted_seen (evaluator tracks cross-step context)
    hist_least = ctx.history_digest.least_trusted_seen
    if hist_least:
        try:
            ht = TrustLevel(hist_least)
            trust_levels.append(ht)
            if ht in _UNTRUSTED:
                action_depends_untrusted = True
            if ht in _ADVERSARY:
                action_depends_adversary = True
        except ValueError:
            pass

    hist_sens = ctx.history_digest.most_sensitive_seen
    if hist_sens:
        try:
            hs = Sensitivity(hist_sens)
            sensitivity_levels.append(hs)
            if hs in _SENSITIVE:
                action_has_sensitive = True
        except ValueError:
            pass

    return TaintResult(
        action_depends_on_untrusted=action_depends_untrusted,
        action_depends_on_adversary=action_depends_adversary,
        action_has_sensitive_source=action_has_sensitive,
        untrusted_texts=untrusted_texts,
        sensitive_texts=sensitive_texts,
        adversary_texts=adversary_texts,
        worst_trust_level=least_trusted(trust_levels) if trust_levels else TrustLevel.AUTHENTICATED_USER,
        worst_sensitivity=most_sensitive(sensitivity_levels) if sensitivity_levels else Sensitivity.PUBLIC,
    )
