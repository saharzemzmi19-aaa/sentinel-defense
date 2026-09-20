"""Provenance node types for the internal provenance graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.core.provenance import Sensitivity, TrustLevel


@dataclass
class ProvenanceNode:
    """A node in the internal provenance graph."""

    node_id: str
    # 'source' | 'content' | 'observation' | 'memory' | 'action' | 'sink'
    node_type: str
    trust_level: TrustLevel
    sensitivity: Sensitivity
    source_id: str
    origin_actor: str
    # The original ProvenanceRecord.id if this maps to an official record
    provenance_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_untrusted(self) -> bool:
        return not self.trust_level.is_trusted

    @property
    def is_adversary_controlled(self) -> bool:
        return self.trust_level.value == "adversary_controlled"

    @property
    def is_sensitive(self) -> bool:
        return self.sensitivity.rank >= Sensitivity.CONFIDENTIAL.rank
