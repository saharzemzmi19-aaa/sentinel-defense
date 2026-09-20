"""Sink classification — generic categories, no scenario-specific names."""

from __future__ import annotations

from enum import StrEnum


class SinkCategory(StrEnum):
    EXTERNAL_COMMUNICATION = "external_communication"
    FINANCIAL_EXECUTION    = "financial_execution"
    STATE_CHANGING         = "state_changing"
    SECURITY_CONFIG        = "security_config"
    MEMORY_PERSISTENCE     = "memory_persistence"
    READ_ONLY              = "read_only"
    UNKNOWN                = "unknown"


def classify_sink(tool: str | None, cfg: dict) -> SinkCategory:
    """Classify a tool name into a SinkCategory using config/defense.yaml sink lists.

    cfg is the ``sink`` sub-dict from defense.yaml.
    Falls back to READ_ONLY if the tool is not in any dangerous category.
    """
    if tool is None:
        return SinkCategory.UNKNOWN

    sink_cfg: dict[str, list[str]] = cfg or {}
    for category in SinkCategory:
        if category in (SinkCategory.READ_ONLY, SinkCategory.UNKNOWN):
            continue
        if tool in sink_cfg.get(str(category), []):
            return category

    return SinkCategory.READ_ONLY


def is_dangerous_sink(category: SinkCategory) -> bool:
    """True for categories that are externally visible or consequential."""
    return category in {
        SinkCategory.EXTERNAL_COMMUNICATION,
        SinkCategory.FINANCIAL_EXECUTION,
        SinkCategory.STATE_CHANGING,
        SinkCategory.SECURITY_CONFIG,
    }
