#!/bin/bash
# Move to script directory
cd "$(dirname "$0")"

# Export package path so relative imports work inside workers
export PYTHONPATH="$PWD/bastion:$PYTHONPATH"

# Execute uvicorn directly from virtual environment
./.venv/bin/uvicorn core.proxy:app --app-dir bastion --host 127.0.0.1 --port 8000 --reload
