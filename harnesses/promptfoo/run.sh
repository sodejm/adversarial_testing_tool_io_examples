#!/usr/bin/env bash
set -euo pipefail

# Directory of this harness
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Running Promptfoo Adversarial Testing Harness ==="

export PROMPTFOO_DISABLE_TELEMETRY=true
export PROMPTFOO_CONFIG_DIR="${REPO_ROOT}/.promptfoo"
mkdir -p "${REPO_ROOT}/examples/promptfoo/inputs"
mkdir -p "${REPO_ROOT}/examples/promptfoo/outputs"

# Copy input config to example inputs
cp "${SCRIPT_DIR}/promptfooconfig.yaml" "${REPO_ROOT}/examples/promptfoo/inputs/promptfooconfig.yaml"

cd "${SCRIPT_DIR}"

CONFIG_FILE="${SCRIPT_DIR}/promptfooconfig.yaml"
RUNTIME_CONFIG=false
if [ -n "${PROMPTFOO_TARGET_URL:-}" ] && [ "${PROMPTFOO_TARGET_URL}" != "http://localhost:8000/v1" ]; then
  CONFIG_FILE="${SCRIPT_DIR}/.promptfooconfig.runtime.yaml"
  sed "s|http://localhost:8000/v1|${PROMPTFOO_TARGET_URL}|g" "${SCRIPT_DIR}/promptfooconfig.yaml" > "${CONFIG_FILE}"
  RUNTIME_CONFIG=true
fi

echo "Executing promptfoo eval..."
PROMPTFOO_CMD="promptfoo"
if ! command -v promptfoo &>/dev/null; then
  PROMPTFOO_CMD="npx promptfoo"
fi

${PROMPTFOO_CMD} eval \
  --config "${CONFIG_FILE}" \
  --output "${REPO_ROOT}/examples/promptfoo/outputs/promptfoo_results.json" \
  --output "${REPO_ROOT}/examples/promptfoo/outputs/promptfoo_summary.html" \
  --no-table \
  --no-progress-bar \
  --max-concurrency 8 || true

if [ "${RUNTIME_CONFIG}" = true ]; then
  rm -f "${CONFIG_FILE}"
fi

echo "Generating SARIF report from Promptfoo results..."
if [ "${IN_CONTAINER:-0}" != "1" ] && [ -f "${REPO_ROOT}/.venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/.venv/bin/activate"
fi

python3 "${REPO_ROOT}/scripts/promptfoo_to_sarif.py" \
  "${REPO_ROOT}/examples/promptfoo/outputs/promptfoo_results.json" \
  "${REPO_ROOT}/examples/promptfoo/outputs/promptfoo_report.sarif"

echo "Promptfoo execution completed. Generated artifacts in examples/promptfoo/outputs/"
