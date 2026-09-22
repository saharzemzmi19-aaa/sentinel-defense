"""Offline, redacted action/decision/outcome viewer for official JSONL traces.

Usage: python observability/dashboard.py --artifacts results/audit/traces --out observability/audit_report.html
Optional --decisions associates the defense's redacted JSONL evidence by run/step.
Raw argument values, user text, model replies and exception messages are omitted.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
from collections import Counter
from pathlib import Path

DEFAULT_ARTIFACTS_DIR = Path('results/audit/traces')
DEFAULT_OUT = Path(__file__).resolve().parent / 'audit_report.html'


def find_jsonl_files(artifacts_dir: Path) -> list[Path]:
    if not artifacts_dir.exists():
        raise FileNotFoundError(artifacts_dir)
    return sorted(artifacts_dir.rglob('*.jsonl'))


def load_events(path: Path) -> list[dict]:
    events = []
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError('Expected an event object')
        events.append(item)
    return events


def summarize_run(events: list[dict], evidence: dict | None = None) -> dict:
    rows = []
    counts: Counter = Counter()
    for event in events:
        if event.get('type') != 'defense_decision':
            continue
        payload = event.get('payload') or {}
        action = payload.get('action') or {}
        step = event.get('step_id')
        outcomes = [e for e in events if e.get('step_id') == step and e.get('type') in
                    {'tool_result', 'retrieval_result', 'human_confirmation', 'policy_violation',
                     'memory_write', 'model_output', 'task_success', 'task_failure'}]
        result = []
        for outcome in outcomes:
            p = outcome.get('payload') or {}
            kind = outcome['type']
            if kind in {'tool_result', 'retrieval_result'}:
                result.append('tool succeeded' if p.get('succeeded') else 'tool failed')
            elif kind == 'human_confirmation':
                result.append('human approved' if p.get('approved') else 'human denied')
            else:
                result.append(kind.replace('_', ' '))
        run_hash = hashlib.sha256(str(event.get('run_id', '')).encode()).hexdigest()[:16]
        trace = (evidence or {}).get((run_hash, step), {})
        safe_evidence = {k: trace[k] for k in (
            'worst_trust_level', 'worst_sensitivity', 'confirmation_required', 'confirmation_present',
            'destination_external', 'sink_category', 'transformations', 'provenance_path',
            'prerequisites_met', 'prerequisites_unresolved', 'policy_finding_count') if k in trace}
        decision = str(payload.get('decision', 'unknown'))
        counts[decision] += 1
        rows.append({'step': step, 'decision': decision, 'risk': payload.get('risk_score'),
                     'confidence': payload.get('confidence'), 'tool': action.get('tool') or action.get('type'),
                     'argument_fields': sorted((action.get('arguments') or {}).keys()),
                     'reasons': payload.get('reason_codes', []), 'outcome': ', '.join(result) or 'stopped / no execution',
                     'error': bool(payload.get('defense_error')), 'evidence': safe_evidence})
    return {'rows': rows, 'counts': counts}


def _escape(value: object) -> str:
    return html.escape(str(value))


def render_run(run_name: str, summary: dict) -> str:
    rows = []
    for row in summary['rows']:
        details = _escape(json.dumps(row['evidence'], indent=2))
        values = [row['step'], row['decision'].upper(), row['risk'], row['confidence'], row['tool'],
                  ', '.join(row['argument_fields']), ', '.join(row['reasons']),
                  ('DEFENSE ERROR; ' if row['error'] else '') + row['outcome']]
        cells = ''.join(f'<td>{_escape(v)}</td>' for v in values)
        rows.append(f'<tr data-decision="{_escape(row["decision"])}">{cells}'
                    f'<td><details><summary>Evidence</summary><pre>{details}</pre></details></td></tr>')
    return (f'<section><h2>{_escape(run_name)}</h2><p>{_escape(dict(summary["counts"]))}</p>'
            '<table><thead><tr><th>Step</th><th>Decision</th><th>Risk</th><th>Confidence</th>'
            '<th>Action</th><th>Argument fields (values redacted)</th><th>Reasons</th><th>Outcome</th>'
            '<th>Evidence</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></section>')


def generate_report(artifacts_dir: Path, out_path: Path, decisions: Path | None = None) -> None:
    evidence = {}
    if decisions:
        for trace in load_events(decisions):
            evidence[(trace.get('request_id'), trace.get('step_id'))] = trace
    sections = []
    for path in find_jsonl_files(artifacts_dir):
        events = load_events(path)
        if any(e.get('type') == 'defense_decision' for e in events):
            sections.append(render_run(str(path.relative_to(artifacts_dir)), summarize_run(events, evidence)))
    document = '''<!doctype html><html lang="en"><meta charset="utf-8"><title>Sentinel decision trace</title>
<style>body{font:14px system-ui;margin:24px;color:#17212b}table{border-collapse:collapse;width:100%}
td,th{padding:8px;border:1px solid #ccd3da;text-align:left}section{margin:32px 0}
[data-decision=block]{background:#fee}[data-decision=escalate]{background:#fff5cd}
[data-decision=allow]{background:#eef9ef}[data-decision=rewrite]{background:#edf3ff}
pre{white-space:pre-wrap;max-width:420px}input,select{padding:8px}</style>
<h1>Sentinel action, decision and outcome trace</h1>
<p>Values and free text are redacted. Expand evidence for provenance, sensitivity, confirmation and transformations.</p>
<label>Find run or reason <input id="search" type="search"></label>
<label>Decision <select id="decision"><option value="">All</option><option>allow</option><option>block</option>
<option>escalate</option><option>rewrite</option></select></label>
''' + ''.join(sections) + '''
<script>function filter(){const q=document.querySelector('#search').value.toLowerCase();
const d=document.querySelector('#decision').value;
for(const s of document.querySelectorAll('section')){let visible=false;
for(const r of s.querySelectorAll('tbody tr')){r.hidden=!!((d&&r.dataset.decision!==d)||
!(s.querySelector('h2').textContent+' '+r.textContent).toLowerCase().includes(q));visible ||= !r.hidden;}s.hidden=!visible;}}
document.querySelector('#search').addEventListener('input',filter);
document.querySelector('#decision').addEventListener('change',filter);</script></html>'''
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(document, encoding='utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, default=DEFAULT_ARTIFACTS_DIR)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    parser.add_argument('--decisions', type=Path)
    args = parser.parse_args()
    generate_report(args.artifacts, args.out, args.decisions)


if __name__ == '__main__':
    main()
