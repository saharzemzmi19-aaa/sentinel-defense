"""Risk fusion supplies descriptive scores; it never overrides policy gates.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from context.builder import NormalizedContext
from dataflow.flow import DataFlowResult
from policy.capabilities import CapabilityResult
from provenance.taint import TaintResult


@dataclass
class RiskScore:
    value: float
    contributing_signals: dict[str, float] = field(default_factory=dict)
    recommend_escalate: bool = True


# Recalibrated: scale (transaction size) dominates, since it's the
# strongest real-world proxy for consequence severity.
_WEIGHTS = {
    "trust": 0.25,
    "sensitivity": 0.15,
    "amount_or_scale": 0.40,
    "reversibility": 0.10,
    "history": 0.10,
}

_ESCALATE_THRESHOLD = 0.35


def _trust_risk(taint: TaintResult) -> float:
    if taint.action_depends_on_untrusted:
        return 0.6
    return 0.1


def _sensitivity_risk(taint: TaintResult) -> float:
    if taint.action_has_sensitive_source:
        return 0.6
    return 0.1


def _scale_risk(ctx: NormalizedContext) -> float:
    """Heuristic transaction scale; this is not a calibrated probability."""
    amount = ctx.arguments.get("amount")
    if isinstance(amount, (int, float)):
        if amount <= 500:
            return 0.1
        if amount <= 2000:
            return 0.35
        if amount <= 10000:
            return 0.6
        return 0.85
    return 0.4  # neutral fallback when no amount field present


def _reversibility_risk(ctx: NormalizedContext, flow: DataFlowResult) -> float:
    if ctx.tool == "email_send" and "email_draft" in ctx.allowed_tools:
        return 0.2
    return 0.5


def _history_risk(ctx: NormalizedContext) -> float:
    if ctx.is_confirmed:
        return 0.2
    return 0.4


def compute_risk(
    ctx: NormalizedContext,
    capabilities: CapabilityResult,
    taint: TaintResult,
    flow: DataFlowResult,
) -> RiskScore:
    signals = {
        "trust": _trust_risk(taint),
        "sensitivity": _sensitivity_risk(taint),
        "amount_or_scale": _scale_risk(ctx),
        "reversibility": _reversibility_risk(ctx, flow),
        "history": _history_risk(ctx),
    }
    fused = sum(_WEIGHTS[k] * v for k, v in signals.items())
    recommend_escalate = fused >= _ESCALATE_THRESHOLD

    return RiskScore(
        value=round(fused, 3),
        contributing_signals=signals,
        recommend_escalate=recommend_escalate,
    )