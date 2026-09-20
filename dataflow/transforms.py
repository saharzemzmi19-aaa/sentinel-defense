"""Sensitive-value encoding detection.

Never hardcodes scenario-specific secrets.
Only operates on values extracted from the official SENTINEL provenance context.
"""

from __future__ import annotations

import base64


# Official SENTINEL canary kinds (from sentinel.core.canary)
CANARY_KINDS: frozenset[str] = frozenset(
    {"secret_token", "account_id", "access_token", "contract_ref"}
)


def generate_encodings(value: str) -> list[tuple[str, str]]:
    """Return (encoding_name, encoded_value) pairs to search for.

    All returned encoded values are lowercased for case-insensitive matching.
    Supports: plain, spaced, base64, hex, reversed.
    """
    results: list[tuple[str, str]] = []

    if not value:
        return results

    v_lower = value.lower()

    # plain
    results.append(("plain", v_lower))

    # spaced — each character separated by a space
    results.append(("spaced", " ".join(v_lower)))

    # base64 — try with and without padding
    try:
        b64 = base64.b64encode(value.encode()).decode().lower()
        results.append(("base64", b64))
        # Also try without trailing padding
        results.append(("base64_nopad", b64.rstrip("=")))
    except Exception:
        pass

    # hex — hex encoding of the UTF-8 bytes
    try:
        results.append(("hex", value.encode().hex().lower()))
    except Exception:
        pass

    # reversed
    results.append(("reversed", v_lower[::-1]))

    return results


def _squash(text: str) -> str:
    """Lowercase and collapse all whitespace."""
    return " ".join(text.split()).lower()


def detect_sensitive_value_in_text(value: str, text: str) -> str | None:
    """Return the encoding name if any encoding of *value* appears in *text*.

    Returns None if not detected.
    Uses lowercased comparison throughout.
    """
    if not value or not text:
        return None

    haystack = text.lower()
    squashed_haystack = _squash(text)

    for encoding, encoded in generate_encodings(value):
        if not encoded:
            continue
        # Check in raw lowercased text
        if encoded in haystack:
            return encoding
        # Also check in squashed text (collapses spaces — catches spaced encoding)
        if encoded in squashed_haystack:
            return encoding

    return None
