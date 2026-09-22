"""Run the unchanged official evaluator with the installed local defense.

This development-only script may load scenarios; the defense never sees labels,
reference plans, fixture paths or the canary registry.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.defense import Phase1Defense, load_config
from sentinel.defenses.baselines.allow_all import AllowAllDefense
from sentinel.evaluator.runner import AttackMode, RunConfig, evaluate, load_suite
from sentinel.storage.runs import ArtifactStore


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--starter-kit', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='Fresh directory for reproducible reports and traces')
    parser.add_argument('--split', default='all', choices=['all', 'public', 'validation'])
    parser.add_argument('--attack-mode', default='static', choices=['static', 'adaptive'])
    parser.add_argument('--allow-all', action='store_true')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    root = args.starter_kit.resolve()
    suite = root / 'scenarios'
    if args.split != 'all':
        suite /= args.split
    config = RunConfig(root=root, attack_mode=AttackMode(args.attack_mode),
                       artifacts=ArtifactStore(args.out / 'traces'))
    factory = AllowAllDefense if args.allow_all else lambda: Phase1Defense(load_config())
    with (args.out / 'decisions.jsonl').open('w') as log, redirect_stderr(log):
        report = evaluate(load_suite(suite), factory, config)
    (args.out / 'scorecard.json').write_text(report.model_dump_json(indent=2), encoding='utf-8')
    print(report.metrics.model_dump_json(indent=2))
    print('Local simulator diagnostics, not an official jury score. Model: mock; run seed: 0.')


if __name__ == '__main__':
    main()
