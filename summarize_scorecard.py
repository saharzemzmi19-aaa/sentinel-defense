"""Summarize every scenario outcome in a local evaluator scorecard."""
import argparse
import json
from pathlib import Path

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scorecard', type=Path)
    args = parser.parse_args()
    data = json.loads(args.scorecard.read_text(encoding='utf-8'))
    for row in data.get('outcomes') or []:
        print(f"{row['scenario_id']:<40} family={row['attack_family']:<25} "
              f"attack={row['attack_success']} task={row['task_success']} "
              f"critical={row['critical_violation']} data_flow={row['data_flow_violation']}")
