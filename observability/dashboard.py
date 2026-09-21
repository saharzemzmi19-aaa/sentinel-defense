"""
observability/dashboard.py

Lit tous les fichiers .jsonl produits par les runs SENTINEL (starter kit)
sous un dossier artifacts/, et genere une page HTML unique et lisible :
un tableau par run, colore par decision (ALLOW/BLOCK/ESCALATE/REWRITE),
avec risk_score, reason_codes, tool, arguments et explanation.

Usage (depuis la racine de sentinel-defense, venv active) :

    python observability\\dashboard.py

Par defaut :
  - lit recursivement C:\\Users\\Gigabyte\\Sentinel_Starter_Kit\\artifacts\\*.jsonl
  - ecrit observability\\trace_report.html

Options :
    python observability\\dashboard.py --artifacts <dossier> --out <fichier.html>
"""

from __future__ import annotations

import argparse
import html
import json
from collections import defaultdict
from pathlib import Path

DEFAULT_ARTIFACTS_DIR = Path(
    r"C:\Users\Gigabyte\Sentinel_Starter_Kit\artifacts"
)
DEFAULT_OUT = Path(__file__).resolve().parent / "trace_report.html"

DECISION_COLORS = {
    "allow": "#1e7e34",       # vert
    "block": "#b02a37",       # rouge
    "escalate": "#e0a800",    # orange
    "rewrite": "#0d6efd",     # bleu
}
DECISION_BG = {
    "allow": "#eaf7ee",
    "block": "#fbe9eb",
    "escalate": "#fff6e0",
    "rewrite": "#e8f0fe",
}


def find_jsonl_files(artifacts_dir: Path) -> list[Path]:
    if not artifacts_dir.exists():
        raise FileNotFoundError(f"Dossier introuvable : {artifacts_dir}")
    return sorted(artifacts_dir.rglob("*.jsonl"))


def load_events(path: Path) -> list[dict]:
    events = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"  [!] Ligne JSON invalide ignoree ({path.name}:{line_no}): {exc}")
    return events


def summarize_run(events: list[dict]) -> dict:
    """Associe chaque defense_decision au contexte (user_message precedent,
    tool_request qui suit), et calcule des compteurs par decision."""
    rows = []
    counts = defaultdict(int)
    last_user_text = None

    for ev in events:
        etype = ev.get("type")
        payload = ev.get("payload", {}) or {}

        if etype == "user_message":
            last_user_text = payload.get("text")

        elif etype == "defense_decision":
            action = payload.get("action", {}) or {}
            decision = str(payload.get("decision", "unknown")).lower()
            counts[decision] += 1
            rows.append(
                {
                    "seq": ev.get("seq"),
                    "step_id": ev.get("step_id"),
                    "timestamp": ev.get("timestamp"),
                    "decision": decision,
                    "risk_score": payload.get("risk_score"),
                    "confidence": payload.get("confidence"),
                    "reason_codes": payload.get("reason_codes") or [],
                    "tool": action.get("tool"),
                    "arguments": action.get("arguments"),
                    "explanation": payload.get("explanation"),
                    "defense_error": payload.get("defense_error"),
                    "context": last_user_text,
                }
            )

    return {"rows": rows, "counts": counts}


def render_badge(decision: str) -> str:
    color = DECISION_COLORS.get(decision, "#555")
    bg = DECISION_BG.get(decision, "#eee")
    label = html.escape(decision.upper())
    return (
        f'<span style="background:{bg};color:{color};font-weight:600;'
        f'padding:2px 8px;border-radius:10px;font-size:12px;">{label}</span>'
    )


def render_run(run_name: str, summary: dict) -> str:
    rows = summary["rows"]
    counts = summary["counts"]

    count_badges = " ".join(
        f'<span style="margin-right:10px;">{render_badge(dec)} &times; {n}</span>'
        for dec, n in sorted(counts.items())
    )

    body_rows = []
    for r in rows:
        reason_codes = ", ".join(html.escape(str(c)) for c in r["reason_codes"])
        args = html.escape(json.dumps(r["arguments"], ensure_ascii=False)) if r["arguments"] else ""
        explanation = html.escape(str(r["explanation"]) or "")
        context = html.escape((r["context"] or "")[:160])
        risk = r["risk_score"]
        risk_str = f"{risk:.2f}" if isinstance(risk, (int, float)) else "—"
        error_flag = (
            f'<div style="color:#b02a37;font-weight:600;">error: {html.escape(str(r["defense_error"]))}</div>'
            if r["defense_error"]
            else ""
        )
        bg = DECISION_BG.get(r["decision"], "#fff")

        body_rows.append(
            f"""
            <tr style="background:{bg};">
              <td>{r["seq"]}</td>
              <td>{render_badge(r["decision"])}</td>
              <td style="text-align:right;">{risk_str}</td>
              <td>{html.escape(r["tool"] or "")}</td>
              <td><code style="font-size:11px;">{args}</code></td>
              <td>{reason_codes}</td>
              <td style="max-width:320px;font-size:12px;color:#333;">{explanation}{error_flag}</td>
              <td style="max-width:220px;font-size:11px;color:#777;">{context}</td>
            </tr>
            """
        )

    return f"""
    <section style="margin-bottom:36px;">
      <h2 style="margin-bottom:4px;">{html.escape(run_name)}</h2>
      <div style="margin-bottom:10px;">{count_badges or "<em>aucune decision de defense trouvee</em>"}</div>
      <table style="border-collapse:collapse;width:100%;font-family:system-ui,sans-serif;font-size:13px;">
        <thead>
          <tr style="text-align:left;border-bottom:2px solid #ccc;">
            <th>#</th><th>Decision</th><th>Risk</th><th>Tool</th>
            <th>Arguments</th><th>Reason codes</th><th>Explanation</th><th>Contexte</th>
          </tr>
        </thead>
        <tbody>
          {''.join(body_rows) if body_rows else '<tr><td colspan="8"><em>—</em></td></tr>'}
        </tbody>
      </table>
    </section>
    """


def generate_report(artifacts_dir: Path, out_path: Path) -> None:
    files = find_jsonl_files(artifacts_dir)
    if not files:
        print(f"[!] Aucun fichier .jsonl trouve sous {artifacts_dir}")

    sections = []
    global_counts = defaultdict(int)

    for path in files:
        print(f"Lecture : {path}")
        events = load_events(path)
        summary = summarize_run(events)
        for dec, n in summary["counts"].items():
            global_counts[dec] += n
        run_name = path.stem
        sections.append(render_run(run_name, summary))

    total_badges = " ".join(
        f'<span style="margin-right:12px;">{render_badge(dec)} &times; {n}</span>'
        for dec, n in sorted(global_counts.items())
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>SENTINEL — Trace Report</title>
</head>
<body style="margin:24px;font-family:system-ui,sans-serif;color:#111;">
  <h1>SENTINEL — Rapport de trace ({len(files)} run(s))</h1>
  <p style="color:#555;">Source : {html.escape(str(artifacts_dir))}</p>
  <div style="margin-bottom:24px;">{total_badges}</div>
  {''.join(sections)}
</body>
</html>
"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_doc, encoding="utf-8")
    print(f"\nRapport genere : {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Genere un rapport HTML a partir des traces SENTINEL")
    parser.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    generate_report(args.artifacts, args.out)


if __name__ == "__main__":
    main()