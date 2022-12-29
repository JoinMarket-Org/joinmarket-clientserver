#!/usr/bin/env bash
# Based on Bitcoin Core's test/lint/lint-python.sh

# The python files in jmqtui/jmqtui are auto generated.
EXCLUDE_PATTERNS="jmqtui/jmqtui/*.py"

if ! command -v flake8 > /dev/null; then
    echo "Skipping Python linting since flake8 is not installed."
    exit 0
elif flake8 --version | grep -q "Python 2"; then
    echo "Skipping Python linting since flake8 is running under Python 2. Install the Python 3 version of flake8."
    exit 0
fi

if [[ $# == 0 ]]; then
    # shellcheck disable=SC2046
    flake8 $(git ls-files "*.py") --extend-exclude "${EXCLUDE_PATTERNS}"
else
    flake8 "$@"
fi
