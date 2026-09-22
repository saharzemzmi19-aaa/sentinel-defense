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
    # Only successful, earlier calls satisfy tool-level prerequisite rules.
    prerequisites_met: bool = True
    missing_prerequisites: list[str] = field(default_factory=list)
    unresolved_prerequisites: bool = False


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
                if rule.get("kind") == "requires_confirmation" and (
                    tool in rule.get("tools", []) if isinstance(rule.get("tools"), list)
                    else ctx.is_consequential
                ):
                    conf_required = True
                    break

    succeeded = {c.tool for c in ctx.history_digest.tool_calls
                 if c.succeeded is True and c.step_id < ctx.step_id
                 and c.decision in {"allow", "escalate", "rewrite"}}
    missing: list[str] = []
    unresolved = False
    for rule in ctx.policy_rules:
        if rule.get("kind") != "prerequisite":
            continue
        if rule.get("tool") == tool and "requires" in rule:
            missing.extend(t for t in rule["requires"] if t not in succeeded)
        elif "tool" not in rule or "requires" not in rule:
            # The current API strips these rule fields. Do not pretend the
            # prerequisite was checked; consequential actions still need review.
            unresolved = True
            # Fixed tool lifecycles published in the reference tool contract.
            # This is tool semantics, never scenario-specific inference.
            predecessor = {"payment_execute": "payment_confirm",
                           "remediation_execute": "remediation_prepare"}.get(tool)
            if predecessor and predecessor not in succeeded:
                missing.append(predecessor)

    return CapabilityResult(
        tool_allowed=tool_allowed,
        confirmation_required=conf_required,
        confirmation_present=ctx.is_confirmed,
        is_consequential=ctx.is_consequential,
        prerequisites_met=not missing,
        missing_prerequisites=sorted(set(missing)),
        unresolved_prerequisites=unresolved,
    )
