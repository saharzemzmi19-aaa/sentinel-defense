"""
SENTINEL Offline Observability Dashboard

Reads official SENTINEL JSONL traces and produces a single
offline HTML report.

The official scenario trace is the PRIMARY source of truth.

Optional defense audit JSONL can provide additional redacted
evidence, but it is matched only when a reliable run/request
association exists. Step ID alone is NEVER treated as a global
identifier.

Usage:

    python observability/dashboard.py `
        --artifacts "C:\\path\\to\\artifact-run" `
        --out "observability\\report.html"

Optional:

    --decisions "results\\audit\\decisions.jsonl"

The report is designed for the SENTINEL demonstration:
- action-by-action decisions
- ALLOW / BLOCK / ESCALATE / REWRITE
- risk score
- confidence
- reason codes
- explanation
- provenance references
- observed outcomes
- safe/redacted evidence
"""

from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

DEFAULT_OUT = (
    Path(__file__).resolve().parent
    / "audit_report.html"
)

DECISION_TYPES = {
    "allow",
    "block",
    "escalate",
    "rewrite",
}


# ============================================================
# JSONL
# ============================================================

def load_jsonl(path: Path) -> list[dict]:
    """
    Load a JSONL file.

    Invalid JSON lines are skipped instead of crashing the
    entire dashboard.
    """

    events: list[dict] = []

    if not path.exists():
        return events

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:

        for line_number, line in enumerate(
            handle,
            start=1,
        ):

            line = line.strip()

            if not line:
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                print(
                    f"[warning] Invalid JSON at "
                    f"{path}:{line_number}"
                )
                continue

            if isinstance(item, dict):
                events.append(item)

    return events


def find_jsonl_files(
    artifacts_dir: Path,
) -> list[Path]:

    if not artifacts_dir.exists():
        raise FileNotFoundError(
            f"Artifacts directory does not exist: "
            f"{artifacts_dir}"
        )

    return sorted(
        artifacts_dir.rglob("*.jsonl")
    )


# ============================================================
# Safe formatting
# ============================================================

def esc(value: object) -> str:
    """
    Safely HTML-escape a value.

    Dictionaries and lists are rendered as JSON.
    """

    if value is None:
        return ""

    if isinstance(
        value,
        (dict, list),
    ):
        value = json.dumps(
            value,
            indent=2,
            ensure_ascii=False,
        )

    return html.escape(
        str(value)
    )


def pretty_json(
    value: object,
) -> str:

    if value in (
        None,
        "",
        [],
        {},
    ):
        return "{}"

    return json.dumps(
        value,
        indent=2,
        ensure_ascii=False,
    )


# ============================================================
# Event helpers
# ============================================================

def get_payload(
    event: dict,
) -> dict:

    payload = event.get(
        "payload"
    )

    if isinstance(
        payload,
        dict,
    ):
        return payload

    return {}


def get_action(
    event: dict,
    payload: dict,
) -> dict:

    action = payload.get(
        "action"
    )

    if isinstance(
        action,
        dict,
    ):
        return action

    return {}


def get_tool(
    action: dict,
    payload: dict,
    event: dict,
) -> str:

    return str(
        action.get("tool")
        or action.get("type")
        or payload.get("tool")
        or event.get("tool")
        or ""
    )


def get_decision(
    payload: dict,
) -> str:

    value = payload.get(
        "decision"
    )

    if value is None:
        return "unknown"

    return str(value).lower()


def get_reasons(
    payload: dict,
) -> list[str]:

    reasons = payload.get(
        "reason_codes"
    )

    if reasons is None:
        return []

    if isinstance(
        reasons,
        str,
    ):
        return [reasons]

    if isinstance(
        reasons,
        list,
    ):
        return [
            str(x)
            for x in reasons
        ]

    return [str(reasons)]


# ============================================================
# Outcome extraction
# ============================================================

def outcome_for_step(
    events: list[dict],
    step_id: object,
) -> list[str]:

    results: list[str] = []

    for event in events:

        if event.get(
            "step_id"
        ) != step_id:
            continue

        event_type = event.get(
            "type"
        )

        payload = get_payload(
            event
        )

        if event_type == "tool_result":

            succeeded = payload.get(
                "succeeded"
            )

            if succeeded is True:
                results.append(
                    "tool succeeded"
                )

            elif succeeded is False:
                results.append(
                    "tool failed"
                )

            else:
                results.append(
                    "tool result"
                )

        elif event_type == "retrieval_result":

            succeeded = payload.get(
                "succeeded"
            )

            if succeeded is True:
                results.append(
                    "retrieval succeeded"
                )

            elif succeeded is False:
                results.append(
                    "retrieval failed"
                )

            else:
                results.append(
                    "retrieval result"
                )

        elif event_type == "human_confirmation":

            approved = payload.get(
                "approved"
            )

            if approved is True:
                results.append(
                    "human approved"
                )

            elif approved is False:
                results.append(
                    "human denied"
                )

            else:
                results.append(
                    "human confirmation"
                )

        elif event_type == "policy_violation":
            results.append(
                "policy violation"
            )

        elif event_type == "memory_write":
            results.append(
                "memory write"
            )

        elif event_type == "model_output":
            results.append(
                "model output"
            )

        elif event_type == "task_success":
            results.append(
                "task success"
            )

        elif event_type == "task_failure":
            results.append(
                "task failure"
            )

    return results


# ============================================================
# Relevant observed content
# ============================================================

def observed_content_for_step(
    events: list[dict],
    step_id: object,
) -> list[dict]:

    observations: list[dict] = []

    for event in events:

        if event.get(
            "step_id"
        ) != step_id:
            continue

        event_type = event.get(
            "type"
        )

        if event_type not in {
            "retrieval_result",
            "tool_result",
            "model_output",
            "memory_write",
        }:
            continue

        payload = get_payload(
            event
        )

        # We deliberately do not dump arbitrary raw content.
        # Only safe metadata is displayed.
        observation = {
            "type": event_type,
            "tool": payload.get(
                "tool"
            ),
            "succeeded": payload.get(
                "succeeded"
            ),
            "provenance_refs": event.get(
                "provenance_refs",
                [],
            ),
        }

        if event_type == "retrieval_result":

            result = payload.get(
                "result"
            )

            if isinstance(
                result,
                dict,
            ):
                observation[
                    "result_fields"
                ] = sorted(
                    result.keys()
                )

        observations.append(
            observation
        )

    return observations


# ============================================================
# Defense audit evidence
# ============================================================

def load_audit_evidence(
    decisions_path: Path | None,
) -> dict:

    """
    Load defense audit data.

    IMPORTANT:
    step_id alone is NOT used as a global key.

    We only retain:
        (request_id, step_id)

    If request_id is missing, the record is not used for
    cross-run matching.
    """

    index: dict[
        tuple[str, int],
        dict,
    ] = {}

    if (
        decisions_path is None
        or not decisions_path.exists()
    ):
        return index

    rows = load_jsonl(
        decisions_path
    )

    for row in rows:

        request_id = row.get(
            "request_id"
        )

        step_id = row.get(
            "step_id"
        )

        if (
            request_id is None
            or step_id is None
        ):
            continue

        try:
            step_id = int(
                step_id
            )
        except (
            TypeError,
            ValueError,
        ):
            continue

        index[
            (
                str(request_id),
                step_id,
            )
        ] = row

    return index


def find_matching_audit(
    event: dict,
    audit_index: dict,
) -> dict:

    """
    Match audit evidence ONLY if the official event has a
    request_id.

    We intentionally do not fallback to step_id because
    step_id is repeated across runs.
    """

    request_id = event.get(
        "request_id"
    )

    step_id = event.get(
        "step_id"
    )

    if (
        request_id is None
        or step_id is None
    ):
        return {}

    try:
        step_id = int(
            step_id
        )
    except (
        TypeError,
        ValueError,
    ):
        return {}

    return audit_index.get(
        (
            str(request_id),
            step_id,
        ),
        {},
    )


# ============================================================
# Evidence
# ============================================================

def build_evidence(
    event: dict,
    payload: dict,
    action: dict,
    audit: dict,
    observations: list[dict],
) -> dict:

    evidence: dict = {}

    # Official trace identifiers
    evidence["run_id"] = event.get(
        "run_id"
    )

    evidence["event_id"] = event.get(
        "event_id"
    )

    evidence["sequence"] = event.get(
        "seq"
    )

    evidence["step_id"] = event.get(
        "step_id"
    )

    # Official provenance
    provenance_refs = event.get(
        "provenance_refs"
    )

    if provenance_refs:
        evidence[
            "provenance_refs"
        ] = provenance_refs

    # Defense explanation
    explanation = payload.get(
        "explanation"
    )

    if explanation:
        evidence[
            "explanation"
        ] = explanation

    # Action metadata
    if action:
        evidence[
            "action"
        ] = {
            "tool": action.get(
                "tool"
            ),
            "type": action.get(
                "type"
            ),
            "argument_fields": sorted(
                (
                    action.get(
                        "arguments"
                    )
                    or {}
                ).keys()
            ),
        }

    # Policy
    policy = event.get(
        "policy"
    )

    if policy:
        evidence[
            "policy"
        ] = policy

    # Rewritten action
    rewritten = payload.get(
        "rewritten_action"
    )

    if rewritten:
        evidence[
            "rewritten_action"
        ] = rewritten

    # Observed event metadata
    if observations:
        evidence[
            "observed_events"
        ] = observations

    # --------------------------------------------------------
    # Optional audit evidence
    # --------------------------------------------------------

    if audit:

        allowed_audit_fields = {
            "worst_trust_level",
            "worst_sensitivity",
            "confirmation_required",
            "confirmation_present",
            "destination_external",
            "sink_category",
            "transformations",
            "provenance_path",
            "prerequisites_met",
            "prerequisites_unresolved",
            "policy_finding_count",
        }

        redacted_audit = {}

        for key in allowed_audit_fields:

            if key in audit:
                redacted_audit[
                    key
                ] = audit[key]

        if redacted_audit:
            evidence[
                "defense_audit"
            ] = redacted_audit

    return evidence


# ============================================================
# Run summarization
# ============================================================

def summarize_run(
    events: list[dict],
    audit_index: dict | None = None,
) -> dict:

    rows: list[dict] = []

    counts: Counter = Counter()

    audit_index = (
        audit_index
        or {}
    )

    for event in events:

        if event.get(
            "type"
        ) != "defense_decision":
            continue

        payload = get_payload(
            event
        )

        action = get_action(
            event,
            payload,
        )

        step = event.get(
            "step_id"
        )

        decision = get_decision(
            payload
        )

        reasons = get_reasons(
            payload
        )

        tool = get_tool(
            action,
            payload,
            event,
        )

        arguments = action.get(
            "arguments"
        ) or {}

        argument_fields = sorted(
            arguments.keys()
        )

        risk = payload.get(
            "risk_score"
        )

        confidence = payload.get(
            "confidence"
        )

        explanation = payload.get(
            "explanation"
        )

        defense_error = payload.get(
            "defense_error"
        )

        rewritten_action = payload.get(
            "rewritten_action"
        )

        outcomes = outcome_for_step(
            events,
            step,
        )

        observations = (
            observed_content_for_step(
                events,
                step,
            )
        )

        audit = find_matching_audit(
            event,
            audit_index,
        )

        evidence = build_evidence(
            event=event,
            payload=payload,
            action=action,
            audit=audit,
            observations=observations,
        )

        counts[
            decision
        ] += 1

        rows.append(
            {
                "step": step,
                "decision": decision,
                "risk": risk,
                "confidence": confidence,
                "tool": tool,
                "argument_fields": argument_fields,
                "reasons": reasons,
                "explanation": explanation,
                "rewritten_action": rewritten_action,
                "outcome": (
                    ", ".join(
                        outcomes
                    )
                    if outcomes
                    else "stopped / no execution"
                ),
                "error": bool(
                    defense_error
                ),
                "evidence": evidence,
            }
        )

    return {
        "rows": rows,
        "counts": counts,
    }


# ============================================================
# HTML
# ============================================================

CSS = r"""
:root {
    --border: #d8dee6;
    --text: #17202a;
    --muted: #667085;
    --background: #f6f8fb;
    --card: #ffffff;
    --allow: #edf8ef;
    --block: #fff0f0;
    --escalate: #fff8df;
    --rewrite: #edf3ff;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 32px;
    font-family:
        Inter,
        Arial,
        Helvetica,
        sans-serif;
    background: var(--background);
    color: var(--text);
}

.container {
    max-width: 1800px;
    margin: auto;
}

h1 {
    margin: 0 0 8px 0;
}

.subtitle {
    color: var(--muted);
    margin-bottom: 28px;
}

.summary {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 28px;
}

.card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 22px;
    min-width: 145px;
}

.card-label {
    font-size: 12px;
    color: var(--muted);
}

.card-value {
    font-size: 26px;
    font-weight: 700;
    margin-top: 4px;
}

.controls {
    background: white;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 28px;
}

.controls input,
.controls select {
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-right: 12px;
}

section {
    background: white;
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 30px;
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 1100px;
}

th {
    background: #eef2f6;
    text-align: left;
    font-size: 12px;
    padding: 11px;
    border-bottom: 1px solid var(--border);
}

td {
    padding: 11px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}

tr[data-decision="allow"] {
    background: var(--allow);
}

tr[data-decision="block"] {
    background: var(--block);
}

tr[data-decision="escalate"] {
    background: var(--escalate);
}

tr[data-decision="rewrite"] {
    background: var(--rewrite);
}

.decision {
    font-weight: 800;
}

.reason {
    display: inline-block;
    padding: 4px 7px;
    border-radius: 5px;
    background: #e9edf2;
    margin: 2px;
    font-size: 12px;
    font-weight: 600;
}

pre {
    white-space: pre-wrap;
    word-break: break-word;
    max-width: 800px;
    margin: 10px 0 0 0;
    padding: 12px;
    background: #f4f6f8;
    border-radius: 7px;
    font-size: 12px;
}

details {
    max-width: 850px;
}

summary {
    cursor: pointer;
    font-weight: 600;
}

.small {
    color: var(--muted);
    font-size: 12px;
}

.highlight {
    font-weight: 800;
}
"""


def render_run(
    run_name: str,
    summary: dict,
) -> str:

    rows_html: list[str] = []

    for row in summary[
        "rows"
    ]:

        decision = row[
            "decision"
        ]

        reasons_html = "".join(
            (
                '<span class="reason">'
                + esc(reason)
                + "</span>"
            )
            for reason in row[
                "reasons"
            ]
        )

        evidence_json = pretty_json(
            row[
                "evidence"
            ]
        )

        error_text = (
            "DEFENSE ERROR; "
            if row["error"]
            else ""
        )

        rows_html.append(
            f"""
<tr data-decision="{esc(decision)}">

<td>
    {esc(row["step"])}
</td>

<td class="decision">
    {esc(decision.upper())}
</td>

<td>
    {esc(row["risk"])}
</td>

<td>
    {esc(row["confidence"])}
</td>

<td>
    <b>{esc(row["tool"])}</b>
</td>

<td>
    {esc(", ".join(row["argument_fields"]))}
</td>

<td>
    {reasons_html}
</td>

<td>
    {esc(error_text + row["outcome"])}
</td>

<td>
    <details>
        <summary>Evidence</summary>
        <pre>{esc(evidence_json)}</pre>
    </details>
</td>

</tr>
"""
        )

    counts = dict(
        summary[
            "counts"
        ]
    )

    return f"""
<section>

<h2>{esc(run_name)}</h2>

<p class="small">
Decision counts:
{esc(counts)}
</p>

<table>

<thead>
<tr>
    <th>Step</th>
    <th>Decision</th>
    <th>Risk</th>
    <th>Confidence</th>
    <th>Action</th>
    <th>Argument fields<br>(values redacted)</th>
    <th>Reasons</th>
    <th>Outcome</th>
    <th>Evidence</th>
</tr>
</thead>

<tbody>

{"".join(rows_html)}

</tbody>

</table>

</section>
"""


# ============================================================
# Report generation
# ============================================================

def generate_report(
    artifacts_dir: Path,
    out_path: Path,
    decisions: Path | None = None,
) -> None:

    print()
    print(
        "=== SENTINEL Observability ==="
    )
    print(
        f"Artifacts : {artifacts_dir}"
    )

    if decisions:
        print(
            f"Audit     : {decisions}"
        )
    else:
        print(
            "Audit     : not supplied"
        )

    # --------------------------------------------------------
    # Audit evidence
    # --------------------------------------------------------

    audit_index = load_audit_evidence(
        decisions
    )

    print(
        f"Audit matches indexed: "
        f"{len(audit_index)}"
    )

    # --------------------------------------------------------
    # Find traces
    # --------------------------------------------------------

    files = find_jsonl_files(
        artifacts_dir
    )

    print(
        f"JSONL files found: "
        f"{len(files)}"
    )

    sections: list[str] = []

    total_decisions = 0
    global_counts: Counter = Counter()

    for path in files:

        events = load_jsonl(
            path
        )

        if not any(
            e.get("type")
            == "defense_decision"
            for e in events
        ):
            continue

        summary = summarize_run(
            events,
            audit_index,
        )

        total_decisions += len(
            summary["rows"]
        )

        global_counts.update(
            summary["counts"]
        )

        sections.append(
            render_run(
                path.name,
                summary,
            )
        )

        print(
            f"  {path.name}: "
            f"{len(summary['rows'])} decisions"
        )

    # --------------------------------------------------------
    # Global summary
    # --------------------------------------------------------

    html_document = f"""
<!doctype html>

<html lang="en">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1"
>

<title>
SENTINEL Observability Report
</title>

<style>
{CSS}
</style>

</head>

<body>

<div class="container">

<h1>
SENTINEL Observability Report
</h1>

<div class="subtitle">

Action-by-action defense trace.

Official scenario JSONL is the primary source.
Raw arguments, user text and model replies are not displayed.

</div>

<div class="summary">

<div class="card">
<div class="card-label">
Defense decisions
</div>
<div class="card-value">
{total_decisions}
</div>
</div>

<div class="card">
<div class="card-label">
ALLOW
</div>
<div class="card-value">
{global_counts.get("allow", 0)}
</div>
</div>

<div class="card">
<div class="card-label">
BLOCK
</div>
<div class="card-value">
{global_counts.get("block", 0)}
</div>
</div>

<div class="card">
<div class="card-label">
ESCALATE
</div>
<div class="card-value">
{global_counts.get("escalate", 0)}
</div>
</div>

<div class="card">
<div class="card-label">
REWRITE
</div>
<div class="card-value">
{global_counts.get("rewrite", 0)}
</div>
</div>

</div>

<div class="controls">

<label>
Search:
<input
    id="search"
    type="search"
    placeholder="run, action, reason..."
>
</label>

<label>
Decision:
<select id="decision">
<option value="">
All
</option>
<option value="allow">
ALLOW
</option>
<option value="block">
BLOCK
</option>
<option value="escalate">
ESCALATE
</option>
<option value="rewrite">
REWRITE
</option>
</select>
</label>

</div>

{"".join(sections)}

</div>

<script>

function filterRows() {{

    const query =
        document
            .getElementById("search")
            .value
            .toLowerCase();

    const decision =
        document
            .getElementById("decision")
            .value;

    document
        .querySelectorAll("section")
        .forEach(section => {{

            let sectionVisible = false;

            section
                .querySelectorAll("tbody tr")
                .forEach(row => {{

                    const text =
                        row.textContent
                            .toLowerCase();

                    const rowDecision =
                        row.dataset.decision;

                    const matchesSearch =
                        !query ||
                        text.includes(query) ||
                        section
                            .querySelector("h2")
                            .textContent
                            .toLowerCase()
                            .includes(query);

                    const matchesDecision =
                        !decision ||
                        rowDecision === decision;

                    const visible =
                        matchesSearch &&
                        matchesDecision;

                    row.hidden =
                        !visible;

                    if (visible) {{
                        sectionVisible = true;
                    }}

                }});

            section.hidden =
                !sectionVisible;

        }});
}}

document
    .getElementById("search")
    .addEventListener(
        "input",
        filterRows
    );

document
    .getElementById("decision")
    .addEventListener(
        "change",
        filterRows
    );

</script>

</body>

</html>
"""

    # --------------------------------------------------------
    # Write
    # --------------------------------------------------------

    out_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    out_path.write_text(
        html_document,
        encoding="utf-8",
    )

    print()
    print(
        f"Report written to: {out_path}"
    )

    print(
        f"Total decisions: {total_decisions}"
    )

    print(
        f"ALLOW: "
        f"{global_counts.get('allow', 0)}"
    )

    print(
        f"BLOCK: "
        f"{global_counts.get('block', 0)}"
    )

    print(
        f"ESCALATE: "
        f"{global_counts.get('escalate', 0)}"
    )

    print(
        f"REWRITE: "
        f"{global_counts.get('rewrite', 0)}"
    )

    print()


# ============================================================
# CLI
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "--artifacts",
        type=Path,
        required=True,
        help=(
            "Official SENTINEL artifact "
            "directory containing JSONL traces."
        ),
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output HTML file.",
    )

    parser.add_argument(
        "--decisions",
        type=Path,
        default=None,
        help=(
            "Optional defense audit JSONL. "
            "Only reliable request_id + step_id "
            "matches are used."
        ),
    )

    args = parser.parse_args()

    generate_report(
        artifacts_dir=args.artifacts,
        out_path=args.out,
        decisions=args.decisions,
    )


if __name__ == "__main__":
    main()