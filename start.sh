#!/usr/bin/env bash
set -e

# Move to script directory
cd "$(dirname "$0")"

# Resolve python interpreter
if [ -f "venv/bin/python" ]; then
    PYTHON_EXEC="venv/bin/python"
elif [ -f ".venv/bin/python" ]; then
    PYTHON_EXEC=".venv/bin/python"
else
    PYTHON_EXEC="python3"
fi

exec "$PYTHON_EXEC" main.py "$@"
