"""Provenance graph — lightweight internal graph for tracking source-to-action chains.

KEY PRINCIPLE: Trust is propagated pessimistically.
  - An untrusted source taints all derived content.
  - Memory does NOT upgrade trust: untrusted -> memory -> action is still untrusted.
  - Reading untrusted content is not itself a violation.
  - Using untrusted content as authority for a consequential action can be.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.actions import ActionType
from sentinel.core.provenance import Sensitivity, TrustLevel, least_trusted, most_sensitive

from context.builder import NormalizedContext
from provenance.edges import ProvenanceEdge
from provenance.nodes import ProvenanceNode


class ProvenanceGraph:
    """Directed acyclic graph tracking content provenance from source to sink."""

    def __init__(self) -> None:
        self._nodes: dict[str, ProvenanceNode] = {}
        # adjacency list: node_id -> list of outgoing edges
        self._out_edges: dict[str, list[ProvenanceEdge]] = {}
        # reverse adjacency: node_id -> list of incoming edges (for ancestor BFS)
        self._in_edges: dict[str, list[ProvenanceEdge]] = {}

    # ── Mutation ──────────────────────────────────────────────────────────────

    def add_node(self, node: ProvenanceNode) -> None:
        self._nodes[node.node_id] = node
        self._out_edges.setdefault(node.node_id, [])
        self._in_edges.setdefault(node.node_id, [])

    def add_edge(self, edge: ProvenanceEdge) -> None:
        self._out_edges.setdefault(edge.source_node_id, []).append(edge)
        self._in_edges.setdefault(edge.target_node_id, []).append(edge)

    # ── Query ─────────────────────────────────────────────────────────────────

    def get_node(self, node_id: str) -> ProvenanceNode | None:
        return self._nodes.get(node_id)

    def ancestors(self, node_id: str) -> list[ProvenanceNode]:
        """BFS over incoming edges — returns all ancestors (not including self)."""
        visited: set[str] = {node_id}
        queue: deque[str] = deque()
        result: list[ProvenanceNode] = []

        for edge in self._in_edges.get(node_id, []):
            parent_id = edge.source_node_id
            if parent_id not in visited:
                visited.add(parent_id)
                queue.append(parent_id)

        while queue:
            nid = queue.popleft()
            node = self._nodes.get(nid)
            if node:
                result.append(node)
            for edge in self._in_edges.get(nid, []):
                parent_id = edge.source_node_id
                if parent_id not in visited:
                    visited.add(parent_id)
                    queue.append(parent_id)

        return result

    def source_trust_level(self, node_id: str) -> TrustLevel:
        """Least-trusted (worst) trust level among all ancestors."""
        levels = [n.trust_level for n in self.ancestors(node_id)]
        node = self._nodes.get(node_id)
        if node:
            levels.append(node.trust_level)
        return least_trusted(levels)

    def source_sensitivity(self, node_id: str) -> Sensitivity:
        """Most-sensitive (worst) sensitivity among all ancestors."""
        levels = [n.sensitivity for n in self.ancestors(node_id)]
        node = self._nodes.get(node_id)
        if node:
            levels.append(node.sensitivity)
        return most_sensitive(levels)

    def depends_on_untrusted(self, node_id: str) -> bool:
        """True if any ancestor (or self) has trust level above TRUSTED_INTERNAL."""
        for node in [self._nodes.get(node_id), *self.ancestors(node_id)]:
            if node and node.is_untrusted:
                return True
        return False

    def depends_on_adversary(self, node_id: str) -> bool:
        """True if any ancestor (or self) is ADVERSARY_CONTROLLED."""
        for node in [self._nodes.get(node_id), *self.ancestors(node_id)]:
            if node and node.is_adversary_controlled:
                return True
        return False

    def has_sensitive_source(self, node_id: str) -> bool:
        """True if any ancestor (or self) has CONFIDENTIAL or RESTRICTED sensitivity."""
        for node in [self._nodes.get(node_id), *self.ancestors(node_id)]:
            if node and node.is_sensitive:
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable summary for tracing. Does not include content."""
        return {
            "nodes": [
                {
                    "id": n.node_id,
                    "type": n.node_type,
                    "trust": n.trust_level.value,
                    "sensitivity": n.sensitivity.value,
                    "origin": n.origin_actor,
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "src": e.source_node_id,
                    "dst": e.target_node_id,
                    "rel": e.relation,
                    "tainted": e.tainted,
                }
                for edges in self._out_edges.values()
                for e in edges
            ],
        }


# ── Builder ────────────────────────────────────────────────────────────────────

def build_provenance_graph(ctx: NormalizedContext) -> ProvenanceGraph:
    """Construct the provenance graph from a NormalizedContext.

    Graph shape:
        source nodes (one per ProvenanceRecord)
            ↓ derived_from
        content nodes (one per ConversationItem + observation)
            ↓ used_by
        action node
            ↓ reaches  (only if external destination)
        sink node
    """
    g = ProvenanceGraph()
    _edge_counter = 0

    def _eid() -> str:
        nonlocal _edge_counter
        _edge_counter += 1
        return f"e{_edge_counter}"

    # ── Source nodes (one per official ProvenanceRecord) ──────────────────────
    for prov_id, rec in ctx.provenance_map.items():
        p = rec.provenance
        node = ProvenanceNode(
            node_id=f"src:{prov_id}",
            node_type="source",
            trust_level=p.trust_level,
            sensitivity=p.sensitivity,
            source_id=p.source_id,
            origin_actor=p.origin_actor,
            provenance_id=prov_id,
            metadata={
                "source_type": p.source_type.value,
                "retrieved_via": p.retrieved_via,
            },
        )
        g.add_node(node)

    # ── Content nodes (one per ConversationItem) ──────────────────────────────
    for idx, item in enumerate(ctx.conversation):
        cid = f"conv:{idx}"
        # Determine trust/sensitivity from provenance references
        refs = [
            ctx.provenance_map[pid].provenance
            for pid in item.provenance_ids
            if pid in ctx.provenance_map
        ]
        trust = least_trusted([r.trust_level for r in refs]) if refs else TrustLevel.AUTHENTICATED_USER
        sens = most_sensitive([r.sensitivity for r in refs]) if refs else Sensitivity.PUBLIC

        cnode = ProvenanceNode(
            node_id=cid,
            node_type="content",
            trust_level=trust,
            sensitivity=sens,
            source_id=";".join(r.source_id for r in refs) or "unknown",
            origin_actor=refs[0].origin_actor if refs else "unknown",
            metadata={"role": item.role, "kind": item.kind},
        )
        g.add_node(cnode)

        # Edge: source -> content
        for pid in item.provenance_ids:
            if pid in ctx.provenance_map:
                src_node_id = f"src:{pid}"
                is_untrusted = g.get_node(src_node_id) and g.get_node(src_node_id).is_untrusted  # type: ignore[union-attr]
                g.add_edge(ProvenanceEdge(
                    edge_id=_eid(),
                    source_node_id=src_node_id,
                    target_node_id=cid,
                    relation="derived_from",
                    tainted=bool(is_untrusted),
                ))

    # ── Observation node ──────────────────────────────────────────────────────
    if ctx.observation is not None:
        obs = ctx.observation
        refs = [
            ctx.provenance_map[pid].provenance
            for pid in obs.provenance_ids
            if pid in ctx.provenance_map
        ]
        trust = least_trusted([r.trust_level for r in refs]) if refs else TrustLevel.AUTHENTICATED_USER
        sens = most_sensitive([r.sensitivity for r in refs]) if refs else Sensitivity.PUBLIC
        obs_node = ProvenanceNode(
            node_id="obs:0",
            node_type="observation",
            trust_level=trust,
            sensitivity=sens,
            source_id=";".join(r.source_id for r in refs) or "unknown",
            origin_actor=refs[0].origin_actor if refs else "unknown",
            metadata={"kind": obs.kind},
        )
        g.add_node(obs_node)
        for pid in obs.provenance_ids:
            if pid in ctx.provenance_map:
                g.add_edge(ProvenanceEdge(
                    edge_id=_eid(),
                    source_node_id=f"src:{pid}",
                    target_node_id="obs:0",
                    relation="derived_from",
                    tainted=False,
                ))

    # ── Action node ───────────────────────────────────────────────────────────
    action_node = ProvenanceNode(
        node_id="action:0",
        node_type="action",
        trust_level=TrustLevel.AUTHENTICATED_USER,  # agent is authenticated user
        sensitivity=Sensitivity.INTERNAL,
        source_id="agent",
        origin_actor="agent",
        metadata={
            "action_type": ctx.action_type.value,
            "tool": ctx.tool or "",
        },
    )
    g.add_node(action_node)

    # Edges: conversation content -> action (used_by)
    for idx, item in enumerate(ctx.conversation):
        cid = f"conv:{idx}"
        cnode = g.get_node(cid)
        if cnode:
            g.add_edge(ProvenanceEdge(
                edge_id=_eid(),
                source_node_id=cid,
                target_node_id="action:0",
                relation="used_by",
                tainted=cnode.is_untrusted,
            ))

    # Observation -> action
    if ctx.observation is not None:
        obs_node = g.get_node("obs:0")
        if obs_node:
            g.add_edge(ProvenanceEdge(
                edge_id=_eid(),
                source_node_id="obs:0",
                target_node_id="action:0",
                relation="used_by",
                tainted=obs_node.is_untrusted,
            ))

    # ── Sink node (only for external destinations) ────────────────────────────
    if ctx.is_external_destination and ctx.destination:
        sink_node = ProvenanceNode(
            node_id="sink:0",
            node_type="sink",
            trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
            sensitivity=Sensitivity.PUBLIC,
            source_id=ctx.destination,
            origin_actor=ctx.destination,
            metadata={"tool": ctx.tool or ""},
        )
        g.add_node(sink_node)
        g.add_edge(ProvenanceEdge(
            edge_id=_eid(),
            source_node_id="action:0",
            target_node_id="sink:0",
            relation="reaches",
            tainted=False,
        ))

    return g
