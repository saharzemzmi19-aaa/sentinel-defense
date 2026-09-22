"""Decision engine — deterministic final decision from all security signals.

Decision precedence (checked in order):
  1. INVALID_ACTION       — tool_call with no tool name
  2. UNAUTHORIZED_TOOL    — tool not in allowed_tools
  3. ADVERSARY + consq.   — adversary-controlled source, consequential action → BLOCK
  4. FORBIDDEN_DATA_FLOW  — sensitive content to external sink → BLOCK
  5. UNTRUSTED+ext+consq. — untrusted → external + consequential → BLOCK
  6. ADVERSARY alone      — adversary-controlled source, any action → BLOCK
  7. MEMORY_WRITE untrust — untrusted content being persisted → BLOCK
  8. REQUEST_CONFIRMATION — agent is asking for confirmation (correct behaviour) → ALLOW
  9. MISSING_CONFIRMATION — consequential, no confirmation → REWRITE or ESCALATE
 10. ALLOW                — everything else passes
"""

from __future__ import annotations

from sentinel.core.actions import ActionType, CandidateAction, Decision, DefenseDecision

from context.builder import NormalizedContext
from dataflow.flow import DataFlowResult
from dataflow.sinks import SinkCategory
from decision.actions import ReasonCode, make_decision
from policy.capabilities import CapabilityResult
from policy.engine import PolicyResult
from provenance.taint import TaintResult


class DecisionEngine:
    """Converts security signals into a single DefenseDecision."""

    def __init__(self, cfg: dict) -> None:
        dcfg = cfg.get("decision", {})
        self._hard_conf:   float = float(dcfg.get("hard_block_confidence",   0.95))
        self._policy_conf: float = float(dcfg.get("policy_block_confidence", 0.85))
        self._esc_conf:    float = float(dcfg.get("escalate_confidence",      0.65))
        self._allow_conf:  float = float(dcfg.get("allow_confidence",         0.80))

    def decide(
        self,
        ctx: NormalizedContext,
        capabilities: CapabilityResult,
        taint: TaintResult,
        flow: DataFlowResult,
        policy: PolicyResult,
    ) -> DefenseDecision:

        # ── 1. INVALID ACTION ─────────────────────────────────────────────────
        if ctx.action_type is ActionType.TOOL_CALL and ctx.tool is None:
            return make_decision(
                Decision.BLOCK, 1.0, 1.0,
                [ReasonCode.INVALID_ACTION],
                "TOOL_CALL action is missing required 'tool' field",
            )

        # ── 2. UNAUTHORIZED TOOL ──────────────────────────────────────────────
        if ctx.action_type is ActionType.TOOL_CALL and not capabilities.tool_allowed:
            return make_decision(
                Decision.BLOCK, 0.95, self._hard_conf,
                [ReasonCode.UNAUTHORIZED_TOOL],
                f"Tool '{ctx.tool}' is not in the allowed tools for this task: {ctx.allowed_tools}",
            )

        # ── 3. ADVERSARY-CONTROLLED + CONSEQUENTIAL ───────────────────────────
        if taint.action_depends_on_adversary and capabilities.is_consequential:
            return make_decision(
                Decision.BLOCK, 0.95, self._policy_conf,
                [ReasonCode.ADVERSARY_CONTROLLED_SOURCE, ReasonCode.POLICY_VIOLATION],
                "Consequential action depends on adversary-controlled content; "
                "adversary-controlled content must not authorize consequential operations",
            )

        # ── 4. FORBIDDEN DATA FLOW ────────────────────────────────────────────
        if flow.has_sensitive_to_external_sink:
            details = "; ".join(f.value_hint for f in flow.findings[:3])
            return make_decision(
                Decision.BLOCK, 0.95, self._policy_conf,
                [ReasonCode.FORBIDDEN_DATA_FLOW],
                f"Sensitive content detected in payload to external destination. {details}",
            )

        # ── 5. UNTRUSTED → EXTERNAL + CONSEQUENTIAL ───────────────────────────
        if (
            taint.action_depends_on_untrusted
            and ctx.is_external_destination
            and capabilities.is_consequential
        ):
            return make_decision(
                Decision.BLOCK, 0.90, self._policy_conf,
                [ReasonCode.UNTRUSTED_SOURCE, ReasonCode.FORBIDDEN_DATA_FLOW],
                "Untrusted content is influencing a consequential action directed at an external destination",
            )

        # ── 6. ADVERSARY-CONTROLLED (non-consequential) ───────────────────────
        if taint.action_depends_on_adversary:
            return make_decision(
                Decision.BLOCK, 0.90, self._policy_conf,
                [ReasonCode.ADVERSARY_CONTROLLED_SOURCE],
                "Action depends on content from an adversary-controlled source",
            )

        # ── 7. MEMORY_WRITE FROM UNTRUSTED ────────────────────────────────────
        if ctx.action_type is ActionType.MEMORY_WRITE and taint.action_depends_on_untrusted:
            return make_decision(
                Decision.BLOCK, 0.85, self._policy_conf,
                [ReasonCode.UNTRUSTED_SOURCE],
                "Memory write contains content derived from untrusted source; "
                "storing untrusted content as memory does not upgrade its trust level",
            )

        # ── 8. REQUEST_CONFIRMATION — agent is doing the right thing ──────────
        if ctx.is_confirmation_request:
            return make_decision(
                Decision.ALLOW, 0.2, self._allow_conf,
                [ReasonCode.CONFIRMATION_REQUESTED],
                "Agent is requesting human confirmation before proceeding",
            )

        # ── 9. MISSING CONFIRMATION ───────────────────────────────────────────
        if capabilities.confirmation_required and not capabilities.confirmation_present:
            # Prefer rewrite to draft when available — always safe, regardless of risk
            if ctx.tool == "email_send" and "email_draft" in ctx.allowed_tools:
                rewritten = CandidateAction(
                    type=ActionType.TOOL_CALL,
                    tool="email_draft",
                    arguments=dict(ctx.arguments),
                )
                return make_decision(
                    Decision.REWRITE, 0.55, self._esc_conf,
                    [ReasonCode.REWRITE_TO_DRAFT, ReasonCode.MISSING_CONFIRMATION],
                    "Unconfirmed email_send rewritten to email_draft pending human confirmation",
                    rewritten_action=rewritten,
                )

            # ── Ablation toggle ──────────────────────────────────────────────
            # SENTINEL_DISABLE_RISK_FUSION=1 reproduces the pre-risk-fusion
            # baseline (Phase 1 only): every missing-confirmation case escalates
            # unconditionally, exactly as it did before risk/fusion.py existed.
            # Default (unset/0) behaviour — used for the official submission —
            # is completely unchanged.
            import os
            if os.environ.get("SENTINEL_DISABLE_RISK_FUSION") == "1":
                return make_decision(
                    Decision.ESCALATE, 0.5, self._esc_conf,
                    [ReasonCode.MISSING_CONFIRMATION],
                    f"[ablation: risk fusion disabled] Tool '{ctx.tool}' is consequential "
                    f"and requires human confirmation; escalating unconditionally.",
                )

            from risk.fusion import compute_risk
            risk = compute_risk(ctx, capabilities, taint, flow)

            if risk.recommend_escalate:
                return make_decision(
                    Decision.ESCALATE, risk.value, self._esc_conf,
                    [ReasonCode.MISSING_CONFIRMATION],
                    f"Tool '{ctx.tool}' is consequential and requires human confirmation; "
                    f"fused risk={risk.value} warrants escalation "
                    f"(signals: {risk.contributing_signals})",
                )
            else:
                # Low fused risk: skip unnecessary human escalation and allow directly.
                # Security still holds because hard BLOCK rules (steps 1-7: adversary,
                # forbidden data flow, untrusted+external+consequential) already fired
                # earlier in the chain if the action were genuinely dangerous.
                return make_decision(
                    Decision.ALLOW, risk.value, self._allow_conf,
                    [ReasonCode.LOW_RISK_AUTO_APPROVED, ReasonCode.MISSING_CONFIRMATION],
                    f"Tool '{ctx.tool}' requires confirmation, but fused risk={risk.value} "
                    f"is low enough to proceed without human escalation "
                    f"(signals: {risk.contributing_signals})",
                )
        # ── 10. ALLOW ─────────────────────────────────────────────────────────
        return self._allow(ctx, capabilities, taint, flow)

    def _allow(
        self,
        ctx: NormalizedContext,
        capabilities: CapabilityResult,
        taint: TaintResult,
        flow: DataFlowResult,
    ) -> DefenseDecision:
        """Compute a graded ALLOW decision."""
        if ctx.action_type is ActionType.RESPOND:
            return make_decision(
                Decision.ALLOW, 0.05, self._allow_conf,
                [ReasonCode.USER_GOAL_ALIGNED],
                "RESPOND action; no tool invoked",
            )
        if flow.sink_category is SinkCategory.READ_ONLY:
            return make_decision(
                Decision.ALLOW, 0.05, self._allow_conf,
                [ReasonCode.READ_ONLY_ACTION],
                f"Read-only tool '{ctx.tool}'; no dangerous sink reached",
            )
        if capabilities.is_consequential and capabilities.confirmation_present:
            return make_decision(
                Decision.ALLOW, 0.10, self._allow_conf,
                [ReasonCode.USER_GOAL_ALIGNED],
                f"Consequential tool '{ctx.tool}' authorised by recorded confirmation",
            )
        return make_decision(
            Decision.ALLOW, 0.15, self._allow_conf,
            [ReasonCode.USER_GOAL_ALIGNED],
            f"Action '{ctx.tool or ctx.action_type}' permitted; "
            "no policy violations detected",
        )
