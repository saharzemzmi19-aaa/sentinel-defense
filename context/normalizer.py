"""Context normalizer — pure helper functions used by the context builder."""

from __future__ import annotations

import re

from sentinel.core.provenance import Sensitivity, TrustLevel

# Tools whose primary purpose is sending content to external recipients
OUTBOUND_TOOLS: frozenset[str] = frozenset(
    {"email_send", "email_draft", "slack_send", "webhook_post", "http_post"}
)

# Argument names that can carry a destination address
_DESTINATION_ARGS: tuple[str, ...] = ("to", "recipient", "url", "endpoint")

# Statuses on update-type tools that make them consequential
STATUS_CONSEQUENTIAL: dict[str, frozenset[str]] = {
    "ticket_update":   frozenset({"closed", "resolved"}),
    "incident_update": frozenset({"closed"}),
}


def squash(text: str) -> str:
    """Lowercase + collapse all whitespace. Used for all text comparisons."""
    return " ".join(text.split()).lower()


def is_outbound_tool(tool: str | None) -> bool:
    return tool in OUTBOUND_TOOLS


def extract_destination(tool: str | None, arguments: dict) -> str | None:
    """Return the lowercased destination value for outbound tools, else None."""
    if not is_outbound_tool(tool):
        return None
    values = [str(arguments[key]).strip().lower() for key in _DESTINATION_ARGS
              if arguments.get(key) is not None]
    # Multiple distinct destinations must all be treated conservatively.
    return ",".join(dict.fromkeys(values)) if values else None


def is_external_destination(destination: str | None, internal_domains: list[str]) -> bool:
    """True when destination is non-empty and not in any internal domain."""
    if not destination:
        return True
    match = re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@([a-z0-9.-]+)", destination.strip(), re.I)
    if match is None:
        return True
    return match[1].lower() not in {d.strip().lower() for d in internal_domains}


def normalize_trust_level(raw: str) -> TrustLevel | None:
    try:
        return TrustLevel(raw)
    except ValueError:
        return None


def normalize_sensitivity(raw: str) -> Sensitivity | None:
    try:
        return Sensitivity(raw)
    except ValueError:
        return None
