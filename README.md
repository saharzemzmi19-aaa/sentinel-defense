# Sentinel Defense

Deterministic safety layer for the IndabaX Tunisia Sentinel simulator. It preserves the official `DefenseRequest` / `DefenseDecision` API, `GET /healthz`, `POST /v1/decision`, and the existing `sentinel-submission.yaml` (port 8081).

The [official specification](https://github.com/Skan22/Sentinel_Starter_Kit) is the governing reference. This audit used the supplied four-page PDF and starter-kit commit `dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`. The starter kit is unchanged. No external inference APIs, models, datasets, or scenario-specific decision rules are used.

See [SECURITY_GAP_ANALYSIS.md](SECURITY_GAP_ANALYSIS.md) for the requirement matrix, historical failures and contract limitations, and [the technical report](report/TECHNICAL_REPORT.md) for results, ablation and the safety statement. Simulator metrics are local evidence; the official score is assigned by a jury, not the `official_score` field in old scorecards.

## Pipeline

```mermaid
flowchart LR
    R[Official request] --> C[Validate and normalize context]
    C --> P[Provenance and inherited taint]
    P --> F[Observed values and disclosure history]
    F --> K[Capabilities and policy]
    K --> D[Decision and mandatory confirmation gate]
    D --> V[Revalidate any rewrite]
    V --> O[Redacted evidence and outcome viewer]
```

- **Context:** validates security-critical policy fields and provenance references; distinguishes internal email destinations using only domains supplied by the trusted policy context.
- **Provenance:** maintains conservative context exposure, graph ancestry and observed copying/encoding into memory. Missing labels on tool/memory content do not grant user authority. Parent event IDs cannot be reconstructed into a complete event graph from the API.
- **Data flow:** extracts values from observed sensitive content, not provenance tags or canary prefixes. Restricted content is checked at replies, memory, drafts and internal notes; confidential content is checked at external destinations. Mixed JSON retrievals are scoped to source record IDs where available. This sensitivity profile is conservative; the API does not expose individual canary destination permissions.
- **Encoding:** plain text, spacing/separators, Base64, hex, reversal, percent encoding, Unicode/JSON escapes, HTML entities, ROT13, and up to three decoding layers. Values need at least 12 normalized characters; this deliberately limits incidental short-text matches.
- **History:** process-local, bounded to 128 active runs, 200,000 characters each of observed sensitive evidence and outgoing history per run. Detects consecutive fragments across fields and actions to the same destination/record. Blocked proposals do not enter outgoing history; reviewed proposals are conservatively retained because execution is not always reported. Restart/eviction loses prior evidence. Use a single worker or sticky routing; this is not distributed storage.
- **Policy:** task tool allowlist, scoped confirmation rules, successful earlier prerequisite calls, published payment/remediation ordering, and visible forbidden effects. Unknown allowed tools require review. The official API omits full prerequisite and effect details; arbitrary indirect effects cannot be guaranteed.
- **Decision:** hard policy/data-flow violations precede review. Mandatory confirmation never depends on transaction amount or risk score. Confirmation uses the official canonical action digest; changed arguments need another grant. The simulator's grants are persistent, not single-use authorizations. A send-to-draft rewrite passes the same pipeline again.
- **Memory:** exact copying of untrusted content is blocked; other untrusted-derived memory proposals go to human review. Reviewed memory retains the simulator's untrusted provenance. This still overblocks some legitimate verbatim memory and does not establish semantic intent.
- **Observability:** structured JSONL on stderr and bounded response metadata contain risk, reasons, trust, sensitivity, confirmation, sink, transformations and hashed provenance references. Argument values, raw destinations and exception text are omitted. The viewer correlates decisions with execution, human confirmation and task outcomes and supports filtering.

An ALLOW means the available checks passed; it does not prove semantic user-goal alignment. Allowed read tools may still retrieve material outside the intended plan. Risk scores are heuristics, not calibrated probabilities.

## Install and run

Use **Python 3.12**, matching the starter kit. Install dependencies once; defense and mock evaluation then run offline.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install /path/to/Sentinel_Starter_Kit
.venv/bin/python -m pytest -q
.venv/bin/python -m uvicorn api.defense:app --host 127.0.0.1 --port 8081 --workers 1
```

The API rejects malformed envelopes/actions with HTTP 422, as the official app does. Invalid nested policy/history data and pipeline exceptions return BLOCK. The official HTTP adapter must retain its default closed fail mode.

## Reproduce evaluation

The audit uses the unchanged official evaluator in-process, mock model, run seed 0. The development script loads scenarios; the runtime defense receives only official requests. Each output directory must be new.

```bash
.venv/bin/python scripts/evaluate.py --starter-kit /path/to/Sentinel_Starter_Kit --out results/local-control --allow-all
.venv/bin/python scripts/evaluate.py --starter-kit /path/to/Sentinel_Starter_Kit --out results/local-final
.venv/bin/python scripts/evaluate.py --starter-kit /path/to/Sentinel_Starter_Kit --out results/local-adaptive --attack-mode adaptive
SENTINEL_DISABLE_RISK_FUSION=1 .venv/bin/python scripts/evaluate.py --starter-kit /path/to/Sentinel_Starter_Kit --out results/local-ablation
```

The risk ablation changes scores only; it never disables confirmation. `--split public` and `--split validation` are optional; the default runs the whole library. For HTTP evaluation, start the service, then run from the starter-kit directory:

```bash
sentinel eval public --defense-url http://127.0.0.1:8081 --model mock
```

Generate a redacted interactive replay:

```bash
.venv/bin/python observability/dashboard.py \
  --artifacts results/local-final/traces \
  --decisions results/local-final/decisions.jsonl \
  --out observability/audit_report.html
```

`inspect_scorecard.py PATH` and `summarize_scorecard.py PATH` accept any scorecard path. The archived `observability/trace_report.html` and three original scorecards remain historical evidence, including service outages and obsolete behavior; use `audit_report.html` for the current implementation.

## Audit results

Baseline: **49 tests passed**. Final: **115 tests passed**, with two dependency deprecation warnings. The former test allowing an unconfirmed small payment was strengthened to require escalation. Added regression coverage includes legitimate controls for each protection.

| Metric, 49 scenarios | Before | After |
|---|---:|---:|
| All tasks completed | 48/49 | 49/49 |
| Benign task utility | 100% | 100% |
| Attack success | 0/35 | 0/35 |
| Critical violations | 0 | 0 |
| Unnecessary escalation rate | 29.73% | 1.08% |
| False block rate, evaluator labels | 1.62% | 4.32% |
| Tool-use integrity | 100% | 88.72% |
| Defense errors | 0 | 0 |

The allow-all control permits all 35 attacks, establishing exposure. After fixes, eight restricted-secret disclosures match loose reference-plan labels and therefore count as false blocks; they remain blocked. Tool-use integrity falls because 15 permitted read calls outside the reference plan now execute instead of being unnecessarily escalated. Neither regression is hidden or described as an improvement. Security improvements beyond the already-zero baseline ASR are demonstrated by paired regression tests, not an invented score gain.

Remaining limits include short/paraphrased/custom-encoded secrets, data absent from observed requests, truncated history, persistent confirmation semantics, unseen indirect effects, and semantic goal alignment. Qwen3-8B was not run; these results concern the mock agent only. A 5–10 minute narrated video, team details and actual submission remain team deliverables.
