"""Tests for risk/fusion.py — verifying that risk fusion reduces
unnecessary escalations (UER) without weakening hard security
guarantees (ASR/CVR stay untouched).
"""

from __future__ import annotations

import pytest

from sentinel.core.actions import Decision

from tests.conftest import make_request, make_tool_call
from tests.test_decision import _decide


def test_low_amount_missing_confirmation_allows_not_escalates():
    """Small payment, missing confirmation, no untrusted content -> ALLOW not ESCALATE"""
    req = make_request(
        make_tool_call("payment_execute", amount=50),
        allowed_tools=["payment_execute"],
        consequential_tools=["payment_execute"],
        confirmation_required_tools=["payment_execute"],
    )
    dec = _decide(req)
    assert dec.decision == Decision.ALLOW
    assert "LOW_RISK_AUTO_APPROVED" in dec.reason_codes

def test_high_amount_missing_confirmation_still_escalates():
    """Large payment still triggers escalation -- high risk preserved"""
    req = make_request(
        make_tool_call("payment_execute", amount=50000),
        allowed_tools=["payment_execute"],
        consequential_tools=["payment_execute"],
        confirmation_required_tools=["payment_execute"],
    )
    dec = _decide(req)
    assert dec.decision == Decision.ESCALATE