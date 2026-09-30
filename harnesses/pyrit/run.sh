#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Running PyRIT Adversarial Testing Harness ==="

export PYRIT_TARGET_URL="${PYRIT_TARGET_URL:-http://localhost:8000/v1}"
export PYRIT_INPUT_DIR="${REPO_ROOT}/examples/pyrit/inputs"
export PYRIT_OUTPUT_DIR="${REPO_ROOT}/examples/pyrit/outputs"

mkdir -p "${PYRIT_INPUT_DIR}"
mkdir -p "${PYRIT_OUTPUT_DIR}"

if [ -f "${REPO_ROOT}/.venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/.venv/bin/activate"
fi

python3 "${SCRIPT_DIR}/pyrit_adversarial_suite.py"

echo "PyRIT execution completed. Generated artifacts in examples/pyrit/outputs/"
