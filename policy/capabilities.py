"""Capability checker — determines what the agent is allowed to do."""

from __future__ import annotations

from dataclasses import dataclass, field

from context.builder import NormalizedContext


@dataclass
class CapabilityResult:
    """What the effective action is allowed to do under current policy."""

    # Is the tool in the allowed_tools list?
    tool_allowed: bool
    # Does this action require human confirmation per policy?
    confirmation_required: bool
    # Has confirmation been previously granted?
    confirmation_present: bool
    # Is this action consequential (financial, state-changing, etc.)?
    is_consequential: bool
    # Prerequisite checking (always True in Phase 1; placeholder for Phase 2)
    prerequisites_met: bool = True
    missing_prerequisites: list[str] = field(default_factory=list)


def check_capabilities(ctx: NormalizedContext) -> CapabilityResult:
    """Check what the agent is allowed to do per the official policy context.

    Uses only information supplied by the evaluator in policy_context.
    """
    tool = ctx.tool
    action_type = ctx.action_type

    # ── Tool allowed ──────────────────────────────────────────────────────────
    # Non-tool actions (RESPOND, MEMORY_WRITE, REQUEST_CONFIRMATION) don't need
    # to be in allowed_tools; only TOOL_CALL does.
    from sentinel.core.actions import ActionType

    tool_allowed: bool
    if action_type is ActionType.TOOL_CALL:
        tool_allowed = tool is not None and tool in ctx.allowed_tools
    else:
        tool_allowed = True  # non-tool actions are always "allowed" at the tool level

    # ── Confirmation required ─────────────────────────────────────────────────
    # confirmation_required_tools: explicitly named tools requiring confirmation
    # consequential_tools: tools the policy marks as consequential (also need confirmation)
    conf_required = False
    if action_type is ActionType.TOOL_CALL and tool is not None:
        if tool in ctx.confirmation_required_tools or ctx.is_consequential:
            conf_required = True
        else:
            for rule in ctx.policy_rules:
                if rule.get("kind") == "requires_confirmation":
                    conf_required = True
                    break

    return CapabilityResult(
        tool_allowed=tool_allowed,
        confirmation_required=conf_required,
        confirmation_present=ctx.is_confirmed,
        is_consequential=ctx.is_consequential,
    )
