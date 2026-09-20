"""Data-flow analyzer — tracks source->derived->action->sink flows."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.core.provenance import Sensitivity

from context.builder import NormalizedContext
from context.normalizer import squash
from dataflow.sinks import SinkCategory, classify_sink, is_dangerous_sink
from dataflow.transforms import detect_sensitive_value_in_text
from provenance.taint import TaintResult

_MIN_OVERLAP = 32   # minimum chars for overlap to count as a taint signal


@dataclass
class FlowFinding:
    """A specific information-flow violation detected in the action payload."""
    value_hint: str        # e.g. 'sensitive content from email-src-123'
    encoding: str          # 'plain', 'base64', 'hex', etc.
    sink_category: SinkCategory
    sensitivity: Sensitivity
    trust_level_str: str   # TrustLevel.value


@dataclass
class DataFlowResult:
    """Result of data-flow analysis for one candidate action."""
    has_sensitive_to_external_sink: bool
    has_untrusted_to_external_sink: bool
    sink_category: SinkCategory
    findings: list[FlowFinding] = field(default_factory=list)


class DataFlowAnalyzer:
    """Deterministic information-flow analysis."""

    def analyze(
        self,
        ctx: NormalizedContext,
        taint: TaintResult,
        cfg: dict,
    ) -> DataFlowResult:
        """Analyze whether dangerous information flows exist in this action.

        Checks:
        1. Sink classification
        2. Sensitive text overlap with action payload (external sink only)
        3. Encoding-aware sensitive value detection (canaries from provenance)
        4. Untrusted text reaching external sink
        """
        sink_cfg = cfg.get("sink", {})
        sink_cat = classify_sink(ctx.tool, sink_cfg)
        dangerous = is_dangerous_sink(sink_cat)
        payload = ctx.action_text_payload
        squashed_payload = squash(payload)
        findings: list[FlowFinding] = []

        has_sensitive_external = False
        has_untrusted_external = False

        # Only check flows if action reaches an external or dangerous sink
        if ctx.is_external_destination or (dangerous and sink_cat != SinkCategory.MEMORY_PERSISTENCE):
            # ── Sensitive text overlap ────────────────────────────────────────
            for sensitive_text in taint.sensitive_texts:
                if not sensitive_text:
                    continue
                needle = squash(sensitive_text)
                # Sliding window: look for MIN_OVERLAP-char substrings
                step = max(1, _MIN_OVERLAP // 2)
                for i in range(0, max(1, len(needle) - _MIN_OVERLAP + 1), step):
                    chunk = needle[i: i + _MIN_OVERLAP]
                    if len(chunk) < 12:
                        break
                    if chunk in squashed_payload:
                        # Find which provenance record this came from
                        for pid, rec in ctx.provenance_map.items():
                            p = rec.provenance
                            if p.sensitivity.rank >= Sensitivity.CONFIDENTIAL.rank:
                                findings.append(FlowFinding(
                                    value_hint=f"sensitive content from {p.source_id}",
                                    encoding="plain",
                                    sink_category=sink_cat,
                                    sensitivity=p.sensitivity,
                                    trust_level_str=p.trust_level.value,
                                ))
                                has_sensitive_external = True
                                break
                        break  # one finding per sensitive text is enough

            # ── Provenance-based sensitive value detection (canaries) ──────────
            for pid, rec in ctx.provenance_map.items():
                p = rec.provenance
                if p.sensitivity.rank < Sensitivity.CONFIDENTIAL.rank:
                    continue
                # Use source_id as the value to check — canary values will appear here
                # if the agent is exfiltrating them
                for tag in p.tags:
                    encoding = detect_sensitive_value_in_text(tag, payload)
                    if encoding:
                        findings.append(FlowFinding(
                            value_hint=f"tagged value from {p.source_id}",
                            encoding=encoding,
                            sink_category=sink_cat,
                            sensitivity=p.sensitivity,
                            trust_level_str=p.trust_level.value,
                        ))
                        has_sensitive_external = True

            # ── Untrusted to external ────────────────────────────────────────
            if taint.action_depends_on_untrusted and ctx.is_external_destination:
                has_untrusted_external = True

        return DataFlowResult(
            has_sensitive_to_external_sink=has_sensitive_external,
            has_untrusted_to_external_sink=has_untrusted_external,
            sink_category=sink_cat,
            findings=findings,
        )
