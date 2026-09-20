"""Shared test fixtures and builder helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from sentinel.core.actions import ActionType, CandidateAction
from sentinel.core.provenance import (
    Provenance,
    Sensitivity,
    SourceType,
    TrustLevel,
)
from sentinel.defenses.interface import (
    ConversationItem,
    DefenseRequest,
    HistoryDigest,
    ProvenanceRecord,
)


# ── Provenance builders ────────────────────────────────────────────────────────

def make_provenance(
    trust_level: TrustLevel,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    source_type: SourceType = SourceType.EMAIL,
    source_id: str = "test-src-1",
    origin_actor: str = "test-actor",
    tags: tuple[str, ...] = (),
) -> Provenance:
    return Provenance(
        source_type=source_type,
        source_id=source_id,
        trust_level=trust_level,
        origin_actor=origin_actor,
        retrieved_via="email_read",
        sensitivity=sensitivity,
        timestamp=datetime.now(timezone.utc),
        parent_event_ids=(),
        tags=tags,
    )


def make_prov_record(
    pid: str,
    trust_level: TrustLevel,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    source_type: SourceType = SourceType.EMAIL,
    source_id: str = "src-1",
    tags: tuple[str, ...] = (),
) -> ProvenanceRecord:
    return ProvenanceRecord(
        id=pid,
        provenance=make_provenance(
            trust_level=trust_level,
            sensitivity=sensitivity,
            source_type=source_type,
            source_id=source_id,
            tags=tags,
        ),
    )


def make_conv_item(
    content: str,
    provenance_ids: list[str],
    role: str = "tool",
    kind: str = "tool_result",
) -> ConversationItem:
    return ConversationItem(
        role=role,
        kind=kind,
        content=content,
        provenance_ids=provenance_ids,
    )


# ── Action builders ────────────────────────────────────────────────────────────

def make_tool_call(tool: str, **arguments: Any) -> CandidateAction:
    return CandidateAction(
        type=ActionType.TOOL_CALL,
        tool=tool,
        arguments=arguments,
    )


def make_respond(content: str, final: bool = True) -> CandidateAction:
    return CandidateAction(
        type=ActionType.RESPOND,
        content=content,
        final=final,
    )


def make_memory_write(content: str) -> CandidateAction:
    return CandidateAction(
        type=ActionType.MEMORY_WRITE,
        content=content,
    )


def make_request_confirmation(inner: CandidateAction) -> CandidateAction:
    return CandidateAction(
        type=ActionType.REQUEST_CONFIRMATION,
        confirmation_for=inner,
    )


# ── DefenseRequest builder ─────────────────────────────────────────────────────

def make_request(
    action: CandidateAction,
    allowed_tools: list[str] | None = None,
    consequential_tools: list[str] | None = None,
    confirmation_required_tools: list[str] | None = None,
    internal_domains: list[str] | None = None,
    prov_records: list[ProvenanceRecord] | None = None,
    conversation: list[ConversationItem] | None = None,
    confirmations_granted: list[str] | None = None,
    policy_rules: list[dict] | None = None,
) -> DefenseRequest:
    return DefenseRequest(
        run_id="test-run",
        step_id=1,
        user_goal="test goal",
        candidate_action=action,
        policy_context={
            "policy_id": "test_policy",
            "policy_version": 1,
            "allowed_tools": allowed_tools or ["email_read", "ticket_read"],
            "consequential_tools": consequential_tools or ["email_send"],
            "confirmation_required_tools": confirmation_required_tools or [],
            "internal_email_domains": internal_domains or ["corp.example"],
            "rules": policy_rules or [],
        },
        provenance=prov_records or [],
        conversation=conversation or [],
        history_digest=HistoryDigest(
            confirmations_granted=confirmations_granted or [],
        ),
    )


# ── Config fixture ─────────────────────────────────────────────────────────────

@pytest.fixture
def defense_cfg() -> dict:
    """Minimal defense config for unit tests."""
    return {
        "decision": {
            "block_at": 0.75,
            "escalate_at": 0.40,
            "hard_block_confidence": 0.95,
            "policy_block_confidence": 0.85,
            "escalate_confidence": 0.65,
            "allow_confidence": 0.80,
        },
        "sink": {
            "external_communication": ["email_send", "email_draft", "slack_send"],
            "financial_execution": ["payment_execute", "payment_confirm"],
            "state_changing": ["ticket_update", "incident_update", "host_isolate"],
            "security_config": ["monitoring_disable", "alert_suppress"],
            "memory_persistence": ["memory_write"],
        },
    }
