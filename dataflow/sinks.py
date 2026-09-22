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
    USER_RESPONSE          = "user_response"


READ_TOOLS = frozenset({
    "email_search", "email_read", "document_search", "document_read", "wiki_search",
    "ticket_read", "customer_lookup", "account_summary", "case_document_read",
    "policy_search", "alert_search", "alert_read", "asset_lookup", "intel_search",
})

# Tool contract, not scenario identities. These are the fields exposed as sinks
# by the official tools. The full action is also checked for external destinations.
SINK_FIELDS = {
    "email_send": ("subject", "body"), "email_draft": ("subject", "body"),
    "ticket_update": ("note",), "case_note_create": ("text",),
    "incident_create": ("title", "summary"), "incident_update": ("note",),
}


def classify_sink(tool: str | None, cfg: dict) -> SinkCategory:
    """Classify a tool name into a SinkCategory using config/defense.yaml sink lists.

    cfg is the ``sink`` sub-dict from defense.yaml.
    Only explicitly known read tools are READ_ONLY; unknown tools need review.
    """
    if tool is None:
        return SinkCategory.UNKNOWN

    sink_cfg: dict[str, list[str]] = cfg or {}
    for category in SinkCategory:
        if category in (SinkCategory.READ_ONLY, SinkCategory.UNKNOWN):
            continue
        if tool in sink_cfg.get(str(category), []):
            return category

    if tool in READ_TOOLS:
        return SinkCategory.READ_ONLY
    if tool in SINK_FIELDS or tool in {"payment_prepare", "remediation_prepare", "remediation_execute"}:
        return SinkCategory.STATE_CHANGING
    return SinkCategory.UNKNOWN


def is_dangerous_sink(category: SinkCategory) -> bool:
    """True for categories that are externally visible or consequential."""
    return category in {
        SinkCategory.EXTERNAL_COMMUNICATION,
        SinkCategory.FINANCIAL_EXECUTION,
        SinkCategory.STATE_CHANGING,
        SinkCategory.SECURITY_CONFIG,
    }
