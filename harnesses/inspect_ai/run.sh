#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Running Inspect AI Adversarial Safety Harness ==="

export INSPECT_TARGET_URL="${INSPECT_TARGET_URL:-http://localhost:8000/v1}"
export INSPECT_INPUT_DIR="${REPO_ROOT}/examples/inspect_ai/inputs"
export INSPECT_OUTPUT_DIR="${REPO_ROOT}/examples/inspect_ai/outputs"

mkdir -p "${INSPECT_INPUT_DIR}"
mkdir -p "${INSPECT_OUTPUT_DIR}"

if [ -f "${REPO_ROOT}/.venv/bin/python3" ]; then
  PYTHON_BIN="${REPO_ROOT}/.venv/bin/python3"
else
  PYTHON_BIN="python3"
fi

"${PYTHON_BIN}" "${SCRIPT_DIR}/inspect_adversarial_task.py"

echo "Inspect AI execution completed. Generated artifacts in examples/inspect_ai/outputs/"
