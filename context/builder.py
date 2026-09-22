"""Context builder — transforms a DefenseRequest into a NormalizedContext.

This is the single entry point from the API layer into the security pipeline.
All downstream components consume NormalizedContext, never raw DefenseRequest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.core.actions import ActionType, CandidateAction
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import (
    ConversationItem,
    DefenseRequest,
    HistoryDigest,
    ObservationView,
    ProvenanceRecord,
)

from context.normalizer import (
    STATUS_CONSEQUENTIAL,
    extract_destination,
    is_external_destination,
    is_outbound_tool,
)


@dataclass
class NormalizedContext:
    """Deterministic, fully-resolved view of a DefenseRequest.

    All fields are populated at construction; no lazy evaluation.
    All text comparisons should use normalizer.squash().
    """

    # ── Identity ─────────────────────────────────────────────────────────────
    run_id: str
    step_id: int
    user_goal: str

    # ── Actions ──────────────────────────────────────────────────────────────
    # The raw candidate action (exactly as received)
    candidate_action: CandidateAction
    # The effective action: unwrapped from REQUEST_CONFIRMATION if needed
    effective_action: CandidateAction
    is_confirmation_request: bool

    # Normalized action fields (from effective_action)
    action_type: ActionType
    tool: str | None
    arguments: dict[str, Any]
    content: str | None

    # ── Policy ───────────────────────────────────────────────────────────────
    allowed_tools: list[str]
    consequential_tools: list[str]
    confirmation_required_tools: list[str]
    internal_email_domains: list[str]
    policy_rules: list[dict]
    policy_id: str
    policy_version: int

    # ── Provenance ───────────────────────────────────────────────────────────
    # Maps provenance_id -> ProvenanceRecord
    provenance_map: dict[str, ProvenanceRecord]

    # ── Conversation & Observation ────────────────────────────────────────────
    conversation: list[ConversationItem]
    observation: ObservationView | None
    history_digest: HistoryDigest

    # ── Derived flags (computed once, used everywhere) ────────────────────────
    is_confirmed: bool
    is_consequential: bool
    action_text_payload: str   # all free text from effective_action
    destination: str | None
    is_external_destination: bool
    forbidden_effects: list[str] = field(default_factory=list)


def build_context(request: DefenseRequest) -> NormalizedContext:
    """Transform an official DefenseRequest into a NormalizedContext.

    Preserves all information from the request — nothing is discarded.
    """
    pc = request.policy_context
    # The official envelope intentionally leaves policy_context untyped. Never
    # let e.g. a string allowlist turn membership into a substring permission.
    for key in ("allowed_tools", "consequential_tools", "confirmation_required_tools",
                "internal_email_domains", "forbidden_effects"):
        value = pc.get(key, [])
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            raise ValueError("Invalid policy list")
    rules = pc.get("rules", [])
    if not isinstance(rules, list) or any(not isinstance(r, dict) for r in rules):
        raise ValueError("Invalid policy rules")
    for rule in rules:
        if rule.get("kind") not in {"tool_permission", "requires_confirmation", "data_flow",
                                    "forbidden_effect", "prerequisite"}:
            raise ValueError("Unsupported policy rule")
        scope = rule.get("tools", "consequential")
        if scope != "consequential" and (not isinstance(scope, list) or
                                         any(not isinstance(x, str) for x in scope)):
            raise ValueError("Invalid confirmation scope")
        if "requires" in rule and (not isinstance(rule["requires"], list) or
                                  not rule["requires"] or
                                  any(not isinstance(x, str) for x in rule["requires"])):
            raise ValueError("Invalid prerequisite")
        if rule.get("kind") == "prerequisite" and (
            ("tool" in rule) != ("requires" in rule)
            or ("tool" in rule and not isinstance(rule["tool"], str))
        ):
            raise ValueError("Incomplete prerequisite rule")
    if len({p.id for p in request.provenance}) != len(request.provenance):
        raise ValueError("Duplicate provenance IDs")
    known_ids = {p.id for p in request.provenance}
    items = [*request.conversation]
    if request.observation is not None:
        items.append(request.observation)
    if any(pid not in known_ids for item in items for pid in item.provenance_ids):
        raise ValueError("Unresolved provenance reference")
    if request.history_digest.least_trusted_seen is not None:
        TrustLevel(request.history_digest.least_trusted_seen)
    if request.history_digest.most_sensitive_seen is not None:
        Sensitivity(request.history_digest.most_sensitive_seen)

    # ── Unwrap REQUEST_CONFIRMATION ───────────────────────────────────────────
    candidate = request.candidate_action
    is_conf_req = candidate.type is ActionType.REQUEST_CONFIRMATION
    effective = (
        candidate.confirmation_for
        if is_conf_req and candidate.confirmation_for is not None
        else candidate
    )

    # ── Policy context fields ─────────────────────────────────────────────────
    allowed_tools: list[str] = pc.get("allowed_tools", [])
    consequential_tools: list[str] = pc.get("consequential_tools", [])
    confirmation_required_tools: list[str] = pc.get("confirmation_required_tools", [])
    internal_domains: list[str] = pc.get("internal_email_domains", [])
    policy_rules: list[dict] = pc.get("rules", [])
    policy_id: str = pc.get("policy_id", "unknown")
    policy_version: int = pc.get("policy_version", 0)

    # ── Provenance map ────────────────────────────────────────────────────────
    prov_map: dict[str, ProvenanceRecord] = {
        rec.id: rec for rec in request.provenance
    }

    # ── is_consequential ──────────────────────────────────────────────────────
    tool = effective.tool
    args = dict(effective.arguments)
    consequential = False
    if effective.type is ActionType.TOOL_CALL and tool is not None:
        if tool in consequential_tools:
            consequential = True
        elif tool in confirmation_required_tools:
            consequential = True
        else:
            status = args.get("status")
            if isinstance(status, str) and status.strip() in STATUS_CONSEQUENTIAL.get(tool, set()):
                consequential = True

    # ── is_confirmed ──────────────────────────────────────────────────────────
    confirmed = effective.digest() in request.history_digest.confirmations_granted

    # ── Destination ───────────────────────────────────────────────────────────
    dest = extract_destination(tool, args)
    ext_dest = is_outbound_tool(tool) and is_external_destination(dest, internal_domains)

    return NormalizedContext(
        run_id=request.run_id,
        step_id=request.step_id,
        user_goal=request.user_goal,
        candidate_action=candidate,
        effective_action=effective,
        is_confirmation_request=is_conf_req,
        action_type=effective.type,
        tool=tool,
        arguments=args,
        content=effective.content,
        allowed_tools=allowed_tools,
        consequential_tools=consequential_tools,
        confirmation_required_tools=confirmation_required_tools,
        internal_email_domains=internal_domains,
        policy_rules=policy_rules,
        policy_id=policy_id,
        policy_version=policy_version,
        provenance_map=prov_map,
        conversation=list(request.conversation),
        observation=request.observation,
        history_digest=request.history_digest,
        is_confirmed=confirmed,
        is_consequential=consequential,
        action_text_payload=effective.text_payload(),
        destination=dest,
        is_external_destination=ext_dest,
        forbidden_effects=list(pc.get("forbidden_effects", [])),
    )
