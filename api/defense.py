"""SENTINEL Phase 1 defense — FastAPI application entry point.

This module:
  1. Loads config/defense.yaml
  2. Instantiates Phase1Defense (implements sentinel.defenses.interface.Defense)
  3. Serves it via sentinel.api.defense_app.create_defense_app()
  4. Runs uvicorn on the configured host/port
"""

from __future__ import annotations

import json
import sys
import time
import hashlib
import threading
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI

from sentinel.api.defense_app import create_defense_app
from sentinel.core.actions import DefenseDecision
from sentinel.defenses.interface import Defense, DefenseRequest

# Local pipeline imports
from context.builder import NormalizedContext, build_context
from dataflow.flow import DataFlowAnalyzer
from decision.engine import DecisionEngine
from policy.capabilities import check_capabilities
from policy.engine import evaluate_policy
from provenance.graph import build_provenance_graph
from provenance.taint import propagate_taint


# ── Config loading ─────────────────────────────────────────────────────────────

_HERE = Path(__file__).parent
_DEFAULT_CONFIG = _HERE.parent / "config" / "defense.yaml"


def load_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or _DEFAULT_CONFIG
    with open(cfg_path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ── Defense implementation ─────────────────────────────────────────────────────

class Phase1Defense(Defense):
    """Deterministic Phase 1 defense.

    Pipeline per request:
        DefenseRequest
          → NormalizedContext          (context/builder.py)
          → ProvenanceGraph + taint    (provenance/)
          → DataFlowResult             (dataflow/)
          → CapabilityResult           (policy/capabilities.py)
          → PolicyResult               (policy/engine.py)
          → DefenseDecision            (decision/engine.py)
    """

    name = "phase1"

    def __init__(self, cfg: dict[str, Any]) -> None:
        self._cfg = cfg
        self._decision_engine = DecisionEngine(cfg)
        self._flow_analyzer = DataFlowAnalyzer()
        self._lock = threading.RLock()

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        t0 = time.monotonic()
        try:
            with self._lock:
                return self._run_pipeline(request, t0)
        except Exception as exc:  # noqa: BLE001
            # Fail-closed: any unhandled exception → BLOCK
            from decision.actions import ReasonCode, make_decision
            from sentinel.core.actions import Decision

            latency_ms = (time.monotonic() - t0) * 1000
            trace = {
                "request_id": hashlib.sha256(str(getattr(request, "run_id", "unknown")).encode()).hexdigest()[:16],
                "decision": "block",
                "reason_codes": [ReasonCode.INTERNAL_ERROR],
                "error_type": type(exc).__name__,
                "latency_ms": round(latency_ms, 2),
            }
            print(json.dumps(trace), file=sys.stderr)
            return make_decision(
                Decision.BLOCK, 1.0, 0.0,
                [ReasonCode.INTERNAL_ERROR],
                f"Internal error; failing closed. ({type(exc).__name__})",
            )

    def _run_pipeline(self, request: DefenseRequest, t0: float) -> DefenseDecision:
        # ── Stage 1: Build context ─────────────────────────────────────────────
        ctx: NormalizedContext = build_context(request)

        # ── Stage 2: Provenance graph + taint ─────────────────────────────────
        graph = build_provenance_graph(ctx)
        taint = propagate_taint(ctx, graph)

        # ── Stage 3: Data-flow analysis ────────────────────────────────────────
        flow = self._flow_analyzer.analyze(ctx, taint, self._cfg)

        # ── Stage 4: Capability check ──────────────────────────────────────────
        capabilities = check_capabilities(ctx)

        # ── Stage 5: Policy evaluation ─────────────────────────────────────────
        policy = evaluate_policy(ctx, capabilities, taint, flow)

        # ── Stage 6: Decision ──────────────────────────────────────────────────
        decision = self._decision_engine.decide(ctx, capabilities, taint, flow, policy)

        from sentinel.core.actions import Decision
        from decision.actions import ReasonCode, make_decision
        if decision.decision is Decision.REWRITE:
            # A draft is a real disclosure sink and has its own policy scope.
            replacement = request.model_copy(update={"candidate_action": decision.rewritten_action})
            checked = self._run_pipeline(replacement, t0)
            if checked.decision is not Decision.ALLOW:
                decision = make_decision(Decision.BLOCK, checked.risk_score, checked.confidence,
                                         [ReasonCode.POLICY_VIOLATION],
                                         "Proposed replacement did not pass all security checks")
        self._flow_analyzer.record(ctx, decision)

        # ── Structured trace → stderr (JSON, one line) ─────────────────────────
        latency_ms = (time.monotonic() - t0) * 1000
        trace = {
            "request_id":                hashlib.sha256(ctx.run_id.encode()).hexdigest()[:16],
            "step_id":                   ctx.step_id,
            "action_type":               ctx.action_type.value,
            "tool":                      ctx.tool,
            "decision":                  decision.decision,
            "reason_codes":              list(decision.reason_codes),
            "risk_score":                decision.risk_score,
            "confidence":                decision.confidence,
            "worst_trust_level":         taint.worst_trust_level.value,
            "worst_sensitivity":         taint.worst_sensitivity.value,
            "action_depends_on_untrusted": taint.action_depends_on_untrusted,
            "action_depends_on_adversary": taint.action_depends_on_adversary,
            "sink_category":             flow.sink_category,
            "has_sensitive_to_external": flow.has_sensitive_to_external_sink,
            "tool_allowed":              capabilities.tool_allowed,
            "confirmation_required":     capabilities.confirmation_required,
            "confirmation_present":      capabilities.confirmation_present,
            "policy_finding_count":      len(policy.findings),
            "prerequisites_met":         capabilities.prerequisites_met,
            "prerequisites_unresolved":  capabilities.unresolved_prerequisites,
            "destination_external":      ctx.is_external_destination,
            "transformations":           sorted({f.encoding for f in flow.findings}),
            "provenance_path":           [
                n.node_type + ":" + hashlib.sha256(n.node_id.encode()).hexdigest()[:8]
                for n in graph.ancestors("action:0")][:24] + ["action:0"],
            "latency_ms":                round(latency_ms, 2),
        }
        print(json.dumps(trace), file=sys.stderr)
        evidence = {k: v for k, v in trace.items() if k not in {"request_id", "latency_ms"}}
        return decision.model_copy(update={"metadata": evidence})

    def close(self) -> None:
        pass  # nothing to tear down in Phase 1


# ── App factory ────────────────────────────────────────────────────────────────

def create_app(cfg: dict[str, Any] | None = None) -> FastAPI:
    """Create and return the FastAPI application."""
    config = cfg or load_config()
    defense = Phase1Defense(config)
    return create_defense_app(defense)


# Singleton app instance for uvicorn / the evaluator
_cfg = load_config()
app: FastAPI = create_app(_cfg)


# ── Entrypoint ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    server_cfg = _cfg.get("server", {})
    uvicorn.run(
        "api.defense:app",
        host=server_cfg.get("host", "0.0.0.0"),
        port=server_cfg.get("port", 8081),
        log_level="info",
    )
