#!/usr/bin/env bash
# shellcheck source=/dev/null
cd "$(dirname "$0")/.." && \
source jmvenv/bin/activate && \
cd scripts && \
python3 joinmarket-qt.py
