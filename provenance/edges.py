"""Provenance edge types for the internal provenance graph."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ProvenanceEdge:
    """A directed edge in the internal provenance graph."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    # Semantic relation:
    #   'derived_from'  — target content was derived from source
    #   'observed_in'   — action observed content from source
    #   'copied_to'     — content was copied/persisted to target
    #   'used_by'       — source influenced the target action
    #   'reaches'       — content reaches a sink
    relation: str
    # True when untrusted trust propagates along this edge
    tainted: bool = False
