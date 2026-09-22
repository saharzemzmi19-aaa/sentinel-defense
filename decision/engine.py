"""Decision engine — deterministic final decision from all security signals.

Hard policy and disclosure violations precede review, confirmation, rewrite and
allow decisions. Context taint is evidence of exposure, not semantic proof that
every subsequent action was caused by an attacker. Risk never grants permission.
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
                f"Tool '{ctx.tool}' is not permitted by the task allowlist",
            )

        if not capabilities.prerequisites_met:
            return make_decision(Decision.BLOCK, 0.9, self._policy_conf,
                                 [ReasonCode.MISSING_PREREQUISITE],
                                 "Required earlier successful tool step is missing")
        if policy.forbidden_effect:
            return make_decision(Decision.BLOCK, 0.95, self._policy_conf,
                                 [ReasonCode.POLICY_VIOLATION],
                                 "Action would cause a forbidden effect")
        # ── 3. ADVERSARY-CONTROLLED + CONSEQUENTIAL ───────────────────────────
        if (taint.action_depends_on_adversary and capabilities.is_consequential
                and not capabilities.confirmation_present and not ctx.is_confirmation_request):
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
                f"Sensitive content would reach a disallowed disclosure sink. {details}",
            )

        if ctx.action_type is ActionType.TOOL_CALL and flow.sink_category is SinkCategory.UNKNOWN:
            return make_decision(Decision.ESCALATE, 0.6, self._esc_conf,
                                 [ReasonCode.UNVERIFIED_CONSEQUENTIAL],
                                 "Allowed tool has unknown effects; human review is required")

        # ── 5. UNTRUSTED → EXTERNAL + CONSEQUENTIAL ───────────────────────────
        if (
            taint.action_depends_on_untrusted
            and ctx.is_external_destination
            and capabilities.is_consequential
            and not capabilities.confirmation_present
            and not ctx.is_confirmation_request
        ):
            return make_decision(
                Decision.BLOCK, 0.90, self._policy_conf,
                [ReasonCode.UNTRUSTED_SOURCE, ReasonCode.FORBIDDEN_DATA_FLOW],
                "Untrusted content is influencing a consequential action directed at an external destination",
            )

        # Context exposure alone is not evidence that every later action is
        # malicious. Reads and harmless replies remain available after attacks.
        if ctx.action_type is ActionType.MEMORY_WRITE and taint.action_depends_on_untrusted:
            from context.normalizer import squash
            copied = squash(ctx.content or "")
            if len(copied) >= 12 and any(copied in squash(t) for t in taint.untrusted_texts):
                return make_decision(
                    Decision.BLOCK, 0.85, self._policy_conf, [ReasonCode.UNTRUSTED_SOURCE],
                    "Untrusted content copied into persistent memory; trust cannot be upgraded",
                )
            return make_decision(
                Decision.ESCALATE, 0.5, self._esc_conf, [ReasonCode.UNTRUSTED_MEMORY_REVIEW],
                "Review derived memory content before persistence; untrusted provenance remains",
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
            # Prefer a draft when available; the API revalidates the replacement.
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

            # Ablation changes only the score, never confirmation enforcement.
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

            # Risk is evidence, never permission to bypass a mandatory rule.
            return make_decision(
                Decision.ESCALATE, risk.value, self._esc_conf,
                [ReasonCode.MISSING_CONFIRMATION],
                "Consequential action requires approval bound to this tool and its arguments",
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
                [ReasonCode.SAFE_ACTION],
                "Response passed the available data-flow and policy checks",
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
                [ReasonCode.SAFE_ACTION],
                f"Consequential tool '{ctx.tool}' authorised by recorded confirmation",
            )
        return make_decision(
            Decision.ALLOW, 0.15, self._allow_conf,
            [ReasonCode.SAFE_ACTION],
            f"Action '{ctx.tool or ctx.action_type}' permitted; "
            "no policy violations detected",
        )
