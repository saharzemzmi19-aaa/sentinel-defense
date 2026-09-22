"""Bounded encoding comparisons over observed values, never canary formats."""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
from urllib.parse import unquote

MAX_SCAN_CHARS = 200_000
MAX_VARIANTS = 32
MAX_DEPTH = 3
_B64 = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")
_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")


def compact(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKC", text).casefold() if c.isalnum())


def generate_encodings(value: str) -> list[tuple[str, str]]:
    if not value:
        return []
    encoded = base64.b64encode(value.encode()).decode()
    return [("plain", value), ("spaced", " ".join(value)), ("base64", encoded),
            ("base64_nopad", encoded.rstrip("=")), ("hex", value.encode().hex()),
            ("reversed", value[::-1])]


def _decoded_tokens(text: str, kind: str) -> str:
    values = []
    for token in (_B64 if kind == "base64" else _HEX).findall(text):
        try:
            raw = (base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
                   if kind == "base64" else bytes.fromhex(token))
            values.append(raw.decode("utf-8"))
        except (ValueError, binascii.Error, UnicodeError):
            continue
    return "\n".join(values)


def text_variants(text: str) -> list[tuple[str, str]]:
    """Decode at most three layers with a total character/variant budget."""
    first = text[:MAX_SCAN_CHARS]
    result = [("plain", first)]
    seen = {first}
    frontier = [("", first)]
    budget = MAX_SCAN_CHARS
    for _ in range(MAX_DEPTH):
        following = []
        for path, value in frontier:
            decoded = [
                ("url", unquote(value)), ("html", html.unescape(value)),
                ("unicode", _ESCAPE.sub(lambda m: chr(int(m[1] or m[2], 16)), value).replace(r"\/", "/")),
                ("base64", _decoded_tokens(value, "base64")),
                ("hex", _decoded_tokens(value, "hex")),
                ("reversed", value[::-1]), ("rot13", codecs.decode(value, "rot_13")),
            ]
            for name, output in decoded:
                if not output or output in seen:
                    continue
                if len(result) >= MAX_VARIANTS or len(output) > budget:
                    continue
                seen.add(output)
                budget -= len(output)
                label = f"{path}+{name}" if path else name
                result.append((label, output))
                following.append((label, output))
        frontier = following
    return result


def detect_sensitive_value_in_text(value: str, text: str) -> str | None:
    if not value or not text:
        return None
    for name, encoded in generate_encodings(value):
        # Base64 is case sensitive. Other supported textual forms follow the
        # evaluator's case-insensitive comparison semantics.
        if name.startswith("base64"):
            if encoded in text:
                return name
        elif encoded.casefold() in text.casefold():
            return name
    needle = compact(value)
    if not needle:
        return None
    for name, variant in text_variants(text):
        if needle in compact(variant):
            return "separators" if name == "plain" else name
    return None
