"""End-to-end precision tests: legitimate work that LOOKS suspicious
must still be ALLOWed. This is the 'over-refusal trap' from the SENTINEL spec —
not covered by test_decision.py's existing 10 tests.
"""

from __future__ import annotations

import pytest

from sentinel.core.actions import Decision
from sentinel.core.provenance import Sensitivity, TrustLevel

from tests.conftest import (
    make_conv_item,
    make_prov_record,
    make_request,
    make_tool_call,
)
from tests.test_decision import _decide
def test_confirmed_payment_allowed_despite_untrusted_context():
    """Even with untrusted content present in conversation, a properly
    confirmed consequential action should ALLOW."""
    prov_untrusted = make_prov_record("p1", TrustLevel.UNTRUSTED_EXTERNAL)
    prov_user = make_prov_record("p2", TrustLevel.AUTHENTICATED_USER)
    conv = [
        make_conv_item("Marketing email, ignore", ["p1"]),
        make_conv_item("User confirms: please send the $200 refund", ["p2"]),
    ]
    action = make_tool_call("payment_execute", amount=200)   # <- créée ici, stockée dans une variable
    req = make_request(
        action,   # <- réutilisée ici
        allowed_tools=["payment_execute"],
        consequential_tools=["payment_execute"],
        confirmation_required_tools=["payment_execute"],
        prov_records=[prov_untrusted, prov_user],
        conversation=conv,
        confirmations_granted=[action.digest()],   # <- fonctionne maintenant
    )
    dec = _decide(req)
    assert dec.decision == Decision.ALLOW