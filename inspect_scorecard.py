"""Inspect the top-level structure of a local scorecard."""
import argparse
import json
from pathlib import Path

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scorecard', type=Path)
    args = parser.parse_args()
    print(list(json.loads(args.scorecard.read_text(encoding='utf-8'))))
