#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Running Garak Adversarial Probing Harness ==="

export GARAK_TARGET_URL="${GARAK_TARGET_URL:-http://localhost:8000/v1}"
export GARAK_CONFIG="${SCRIPT_DIR}/garak_probes.yaml"
export GARAK_INPUT_DIR="${REPO_ROOT}/examples/garak/inputs"
export GARAK_OUTPUT_DIR="${REPO_ROOT}/examples/garak/outputs"

mkdir -p "${GARAK_INPUT_DIR}"
mkdir -p "${GARAK_OUTPUT_DIR}"

if [ -f "${REPO_ROOT}/.venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/.venv/bin/activate"
fi

python3 "${SCRIPT_DIR}/garak_adversarial_runner.py" \
  --config "${GARAK_CONFIG}" \
  --target-url "${GARAK_TARGET_URL}" \
  --input-dir "${GARAK_INPUT_DIR}" \
  --output-dir "${GARAK_OUTPUT_DIR}"

echo "Garak execution completed. Generated artifacts in examples/garak/outputs/"
