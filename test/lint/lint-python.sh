#!/usr/bin/env bash
# Based on Bitcoin Core's test/lint/lint-python.sh

if ! command -v ruff > /dev/null; then
    echo "Skipping Python linting since ruff is not installed."
    exit 0
fi

if [[ $# == 0 ]]; then
    ruff check .
else
    ruff check "$@"
fi
