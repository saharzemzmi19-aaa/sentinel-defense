"""Policy engine — evaluates security constraints from provenance, data-flow, and capabilities."""

from __future__ import annotations

from dataclasses import dataclass, field

from context.builder import NormalizedContext
from dataflow.flow import DataFlowResult
from policy.capabilities import CapabilityResult
from provenance.taint import TaintResult


@dataclass
class PolicyResult:
    """Structured output from the policy engine."""

    # ── Tool permission ───────────────────────────────────────────────────────
    tool_allowed: bool
    # ── Confirmation ─────────────────────────────────────────────────────────
    confirmation_required: bool
    confirmation_present: bool
    # ── Data flow ─────────────────────────────────────────────────────────────
    data_flow_allowed: bool
    # ── Overall ───────────────────────────────────────────────────────────────
    has_violation: bool
    violation_severity: str   # 'critical' | 'high' | 'medium' | 'low' | ''
    findings: list[str] = field(default_factory=list)
    rule_ids_violated: list[str] = field(default_factory=list)


def evaluate_policy(
    ctx: NormalizedContext,
    capabilities: CapabilityResult,
    taint: TaintResult,
    flow: DataFlowResult,
) -> PolicyResult:
    """Evaluate all policy constraints and return a structured PolicyResult.

    Uses official policy rules from ctx.policy_rules (populated by the evaluator).
    """
    findings: list[str] = []
    rule_ids: list[str] = []
    violation_severity = ""
    has_violation = False
    data_flow_allowed = True

    # ── 1. Tool permission ────────────────────────────────────────────────────
    if not capabilities.tool_allowed and ctx.tool is not None:
        has_violation = True
        violation_severity = _worst("critical", violation_severity)
        msg = f"Tool '{ctx.tool}' is not in allowed_tools: {ctx.allowed_tools}"
        findings.append(msg)
        rule_ids.extend(_rule_ids_of_kind(ctx, "tool_permission"))

    # ── 2. Confirmation ───────────────────────────────────────────────────────
    # (Not a hard violation here — the decision engine decides ESCALATE vs BLOCK)
    # We still record it as a policy finding.
    if capabilities.confirmation_required and not capabilities.confirmation_present:
        findings.append(
            f"Tool '{ctx.tool}' requires confirmation but none recorded "
            f"(consequential={capabilities.is_consequential})"
        )
        rule_ids.extend(_rule_ids_of_kind(ctx, "requires_confirmation"))
        # Not setting has_violation=True here — decision engine handles this

    # ── 3. Sensitive data to untrusted sink ───────────────────────────────────
    if flow.has_sensitive_to_external_sink:
        has_violation = True
        data_flow_allowed = False
        violation_severity = _worst("critical", violation_severity)
        findings.append(
            f"Sensitive content detected in payload to external destination '{ctx.destination}'"
        )
        rule_ids.extend(_rule_ids_of_kind(ctx, "data_flow"))
        for ff in flow.findings:
            findings.append(f"  [{ff.encoding}] {ff.value_hint} → {ff.sink_category}")

    # ── 4. Adversary-controlled source → consequential action ─────────────────
    if taint.action_depends_on_adversary and capabilities.is_consequential:
        has_violation = True
        violation_severity = _worst("critical", violation_severity)
        findings.append(
            "Consequential action depends on adversary-controlled content"
        )

    # ── 5. Adversary-controlled source → any action ───────────────────────────
    elif taint.action_depends_on_adversary:
        has_violation = True
        violation_severity = _worst("high", violation_severity)
        findings.append("Action depends on adversary-controlled content")

    # ── 6. Untrusted source → external + consequential ────────────────────────
    if (
        taint.action_depends_on_untrusted
        and ctx.is_external_destination
        and capabilities.is_consequential
        and not taint.action_depends_on_adversary  # already reported above
    ):
        has_violation = True
        data_flow_allowed = False
        violation_severity = _worst("high", violation_severity)
        findings.append(
            "Untrusted content reaching external destination in a consequential action"
        )

    # ── 7. Memory write from untrusted ────────────────────────────────────────
    from sentinel.core.actions import ActionType
    if ctx.action_type is ActionType.MEMORY_WRITE and taint.action_depends_on_untrusted:
        has_violation = True
        violation_severity = _worst("high", violation_severity)
        findings.append(
            "MEMORY_WRITE action contains content derived from untrusted source "
            "(trust is NOT upgraded by storing to memory)"
        )

    return PolicyResult(
        tool_allowed=capabilities.tool_allowed,
        confirmation_required=capabilities.confirmation_required,
        confirmation_present=capabilities.confirmation_present,
        data_flow_allowed=data_flow_allowed,
        has_violation=has_violation,
        violation_severity=violation_severity,
        findings=findings,
        rule_ids_violated=rule_ids,
    )


# ── Helpers ────────────────────────────────────────────────────────────────────

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}


def _worst(a: str, b: str) -> str:
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


def _rule_ids_of_kind(ctx: NormalizedContext, kind: str) -> list[str]:
    return [r.get("id", "") for r in ctx.policy_rules if r.get("kind") == kind]
