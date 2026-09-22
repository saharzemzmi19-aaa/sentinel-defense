"""Observed source-to-sink flows, including bounded same-run disclosure history."""
from __future__ import annotations

import json
import re
from collections import OrderedDict
from dataclasses import dataclass, field

from sentinel.core.actions import ActionType, Decision, DefenseDecision
from sentinel.core.provenance import Sensitivity

from context.builder import NormalizedContext
from dataflow.sinks import SINK_FIELDS, SinkCategory, classify_sink
from dataflow.transforms import compact, text_variants
from provenance.taint import TaintResult


@dataclass
class FlowFinding:
    value_hint: str
    encoding: str
    sink_category: SinkCategory
    sensitivity: Sensitivity
    trust_level_str: str


@dataclass
class DataFlowResult:
    # Kept for compatibility with existing layers; now means a forbidden
    # disclosure, including restricted data at internal and response sinks.
    has_sensitive_to_external_sink: bool
    has_untrusted_to_external_sink: bool
    sink_category: SinkCategory
    findings: list[FlowFinding] = field(default_factory=list)


@dataclass
class _RunFlows:
    sources: dict[tuple[str, str], Sensitivity] = field(default_factory=dict)
    outgoing: dict[str, str] = field(default_factory=dict)
    last_step: int = 0
    recorded_steps: set[int] = field(default_factory=set)


def _leaves(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for item in value for s in _leaves(item)]
    if isinstance(value, dict):
        return [s for key, item in value.items()
                if key not in {"id", "_meta", "status", "timestamp", "title"} and not key.endswith("_id")
                for s in _leaves(item)]
    return []


def _values(text: str) -> set[str]:
    """General observed text values; no canary prefix or secret-field dictionary."""
    try:
        leaves = _leaves(json.loads(text))
    except (ValueError, TypeError):
        leaves = [text]
    values: set[str] = set()
    for leaf in leaves:
        # Full scalar, long tokens (including embedded credentials), and content
        # windows. Short incidental words/numbers are deliberately excluded.
        values.add(leaf)
        values.update(re.findall(r"[\w/+@.=-]{12,}", leaf))
        if len(leaf) > 32:
            values.update(leaf[i:i + 32] for i in range(0, len(leaf) - 31, 16))
    return {compact(v) for v in values if len(compact(v)) >= 12}


def _source_content(text: str, source_id: str) -> str:
    """Scope a mixed retrieval to the record named by its provenance, if present."""
    try:
        value = json.loads(text)
    except ValueError:
        return text
    matches: list[dict] = []

    def visit(item: object) -> None:
        if isinstance(item, dict):
            if item.get("id") == source_id:
                matches.append(item)
            else:
                for child in item.values():
                    visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return json.dumps(matches, ensure_ascii=False) if matches else text


def _sink_payload(ctx: NormalizedContext) -> str:
    if ctx.action_type in {ActionType.RESPOND, ActionType.MEMORY_WRITE}:
        return ctx.content or ""
    fields = SINK_FIELDS.get(ctx.tool or "")
    if fields is not None:
        parts = [str(ctx.arguments[k]) for k in fields if ctx.arguments.get(k) is not None]
        return "\n".join(parts)
    return ctx.action_text_payload


def _sink_key(ctx: NormalizedContext) -> str:
    if ctx.destination:
        return "destination:" + ctx.destination
    if ctx.action_type is ActionType.RESPOND:
        return "user_response"
    if ctx.action_type is ActionType.MEMORY_WRITE:
        return "memory"
    # Repeated notes to the same record can jointly disclose a value.
    targets = {k: v for k, v in ctx.arguments.items() if k.endswith("_id")}
    return f"{ctx.tool}:{json.dumps(targets, sort_keys=True)}"


class DataFlowAnalyzer:
    """Bounded process-local history; only observed request data is retained.

    No evaluator state/labels/files are read. The API serializes decide/record.
    Fresh instances remain usable by stateless in-process integrations.
    """

    def __init__(self) -> None:
        self._runs: OrderedDict[str, _RunFlows] = OrderedDict()

    def _state(self, ctx: NormalizedContext) -> _RunFlows:
        state = self._runs.get(ctx.run_id)
        if state is None or (ctx.step_id == 1 and state.last_step > 1):
            state = _RunFlows()
            self._runs[ctx.run_id] = state
        self._runs.move_to_end(ctx.run_id)
        while len(self._runs) > 128:
            self._runs.popitem(last=False)
        state.last_step = max(state.last_step, ctx.step_id)
        return state

    def analyze(self, ctx: NormalizedContext, taint: TaintResult, cfg: dict) -> DataFlowResult:
        state = self._state(ctx)
        items = list(ctx.conversation)
        if ctx.observation is not None:
            items.append(ctx.observation)
        for item in items:
            refs = [ctx.provenance_map[p].provenance for p in item.provenance_ids if p in ctx.provenance_map]
            for prov in refs:
                if prov.sensitivity.rank >= Sensitivity.CONFIDENTIAL.rank:
                    content = _source_content(item.content, prov.source_id)
                    state.sources[(prov.sensitivity.value, content)] = prov.sensitivity
        # Source sensitivity persists across steps, even when the new memory
        # record omits it. Comparisons always use the originally observed values.
        if sum(len(text) for _, text in state.sources) > 200_000:
            raise ValueError("Sensitive evidence budget exceeded")

        sink = classify_sink(ctx.tool, cfg.get("sink", {}))
        if ctx.action_type is ActionType.RESPOND:
            sink = SinkCategory.USER_RESPONSE
        elif ctx.action_type is ActionType.MEMORY_WRITE:
            sink = SinkCategory.MEMORY_PERSISTENCE
        is_sink = sink is not SinkCategory.READ_ONLY
        findings: list[FlowFinding] = []
        if is_sink:
            payload = _sink_payload(ctx)
            prior = state.outgoing.get(_sink_key(ctx), "")
            if len(prior) + len(payload) > 200_000:
                raise ValueError("Disclosure scan budget exceeded")
            scan_payload = payload
            if ctx.is_external_destination and ctx.destination:
                scan_payload += "\n" + ctx.destination
            variants = [(name, compact(value)) for name, value in text_variants(scan_payload)]
            if prior:
                variants += [("multi_action:" + name, compact(value))
                             for name, value in text_variants(prior + "\n" + payload)]
            for (_, text), sensitivity in state.sources.items():
                forbidden = sensitivity is Sensitivity.RESTRICTED or ctx.is_external_destination
                if not forbidden:
                    continue
                values = _values(text)
                found = next((name for name, value in variants if any(v in value for v in values)), None)
                if found:
                    findings.append(FlowFinding("observed sensitive content [redacted]", found, sink,
                                                sensitivity, taint.worst_trust_level.value))
                    if len(findings) >= 8:
                        break
        return DataFlowResult(bool(findings), taint.action_depends_on_untrusted and ctx.is_external_destination,
                              sink, findings)

    def record(self, ctx: NormalizedContext, decision: DefenseDecision) -> None:
        """Accumulate allowed disclosures, not blocked proposals or confirmation prompts.

        An escalation may execute immediately after approval, so retaining that
        candidate is conservative. The request contract does not report whether
        non-tool escalations were accepted. This can overestimate prior disclosure.
        """
        if ctx.is_confirmation_request or decision.decision is Decision.BLOCK:
            return
        if classify_sink(ctx.tool, {}) is SinkCategory.READ_ONLY:
            return
        state = self._state(ctx)
        if ctx.step_id in state.recorded_steps:
            return
        payload = _sink_payload(ctx)
        key = _sink_key(ctx)
        combined = state.outgoing.get(key, "") + "\n" + payload
        if sum(len(v) for k, v in state.outgoing.items() if k != key) + len(combined) > 200_000:
            raise ValueError("Disclosure history budget exceeded")
        state.outgoing[key] = combined
        state.recorded_steps.add(ctx.step_id)
