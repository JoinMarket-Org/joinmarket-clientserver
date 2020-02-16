#!/usr/bin/env bash
cd $(dirname "$0")/.. && \
source jmvenv/bin/activate && \
cd scripts && \
python3 joinmarket-qt.py
