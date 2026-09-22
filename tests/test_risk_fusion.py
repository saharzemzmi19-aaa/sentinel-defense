"""Tests for risk/fusion.py — verifying that risk fusion reduces
unnecessary escalations (UER) without weakening hard security
guarantees (ASR/CVR stay untouched).
"""

from __future__ import annotations

import pytest

from sentinel.core.actions import Decision

from tests.conftest import make_request, make_tool_call
from tests.test_decision import _decide


def test_low_amount_missing_confirmation_requires_approval():
    """Regression: small amounts cannot override a mandatory confirmation rule.

    The former ALLOW assertion endorsed the audited vulnerability. This
    replacement strengthens the security requirement instead of removing it.
    """
    req = make_request(
        make_tool_call("payment_execute", amount=50),
        allowed_tools=["payment_execute"],
        consequential_tools=["payment_execute"],
        confirmation_required_tools=["payment_execute"],
    )
    dec = _decide(req)
    assert dec.decision == Decision.ESCALATE
    assert "MISSING_CONFIRMATION" in dec.reason_codes
    assert "LOW_RISK_AUTO_APPROVED" not in dec.reason_codes

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
