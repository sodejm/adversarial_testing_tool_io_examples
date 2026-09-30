#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Running DeepTeam / DeepEval Adversarial Safety Harness ==="

export DEEPTEAM_TARGET_URL="${DEEPTEAM_TARGET_URL:-http://localhost:8000/v1}"
export DEEPTEAM_INPUT_DIR="${REPO_ROOT}/examples/deepteam/inputs"
export DEEPTEAM_OUTPUT_DIR="${REPO_ROOT}/examples/deepteam/outputs"

mkdir -p "${DEEPTEAM_INPUT_DIR}"
mkdir -p "${DEEPTEAM_OUTPUT_DIR}"

if [ -f "${REPO_ROOT}/.venv/bin/python3" ]; then
  PYTHON_BIN="${REPO_ROOT}/.venv/bin/python3"
else
  PYTHON_BIN="python3"
fi

"${PYTHON_BIN}" "${SCRIPT_DIR}/deepteam_adversarial_suite.py"

echo "DeepTeam execution completed. Generated artifacts in examples/deepteam/outputs/"
