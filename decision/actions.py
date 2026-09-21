"""Decision actions, reason codes, and the make_decision helper."""

from __future__ import annotations

from enum import StrEnum

from sentinel.core.actions import CandidateAction, Decision, DefenseDecision


class ReasonCode(StrEnum):
    # ── Hard blocks ──────────────────────────────────────────────────────────
    UNAUTHORIZED_TOOL          = "UNAUTHORIZED_TOOL"
    FORBIDDEN_DATA_FLOW        = "FORBIDDEN_DATA_FLOW"
    ADVERSARY_CONTROLLED_SOURCE = "ADVERSARY_CONTROLLED_SOURCE"
    UNTRUSTED_SOURCE           = "UNTRUSTED_SOURCE"
    POLICY_VIOLATION           = "POLICY_VIOLATION"
    INVALID_ACTION             = "INVALID_ACTION"
    INTERNAL_ERROR             = "INTERNAL_ERROR"
    # ── Escalations ──────────────────────────────────────────────────────────
    MISSING_CONFIRMATION       = "MISSING_CONFIRMATION"
    UNVERIFIED_CONSEQUENTIAL   = "UNVERIFIED_CONSEQUENTIAL"
    # ── Allows ───────────────────────────────────────────────────────────────
    SAFE_ACTION                = "SAFE_ACTION"
    CONFIRMATION_REQUESTED     = "CONFIRMATION_REQUESTED"
    READ_ONLY_ACTION           = "READ_ONLY_ACTION"
    USER_GOAL_ALIGNED          = "USER_GOAL_ALIGNED"
    # ── Rewrites ─────────────────────────────────────────────────────────────
    REWRITE_TO_DRAFT           = "REWRITE_TO_DRAFT"
    LOW_RISK_AUTO_APPROVED = "LOW_RISK_AUTO_APPROVED"


def make_decision(
    decision: Decision,
    risk_score: float,
    confidence: float,
    reason_codes: list[ReasonCode | str],
    explanation: str | None = None,
    rewritten_action: CandidateAction | None = None,
) -> DefenseDecision:
    """Build a DefenseDecision, clamping scores to [0, 1]."""
    clamped_risk = round(min(1.0, max(0.0, risk_score)), 4)
    clamped_conf = round(min(1.0, max(0.0, confidence)), 4)
    codes = [str(rc) for rc in reason_codes]
    # Truncate explanation to 500 chars (official limit)
    if explanation and len(explanation) > 500:
        explanation = explanation[:497] + "..."
    return DefenseDecision(
        decision=decision,
        risk_score=clamped_risk,
        confidence=clamped_conf,
        reason_codes=codes,
        explanation=explanation,
        rewritten_action=rewritten_action,
    )
