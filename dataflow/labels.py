"""Flow labels for the data-flow analysis layer."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.core.provenance import Provenance, Sensitivity, TrustLevel


@dataclass(frozen=True)
class FlowLabel:
    """Attached to every piece of data flowing through the system."""

    trust: TrustLevel
    sensitivity: Sensitivity
    origin: str       # source_id or 'unknown'
    source_type: str  # SourceType.value

    @property
    def is_untrusted(self) -> bool:
        return not self.trust.is_trusted

    @property
    def is_adversary(self) -> bool:
        return self.trust.value == "adversary_controlled"

    @property
    def is_sensitive(self) -> bool:
        return self.sensitivity.rank >= Sensitivity.CONFIDENTIAL.rank


def label_for_provenance(p: Provenance) -> FlowLabel:
    """Create a FlowLabel from an official Provenance record."""
    return FlowLabel(
        trust=p.trust_level,
        sensitivity=p.sensitivity,
        origin=p.source_id,
        source_type=p.source_type.value,
    )
