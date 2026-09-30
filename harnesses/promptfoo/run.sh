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

echo "Executing promptfoo eval..."
npx promptfoo eval \
  --config "${SCRIPT_DIR}/promptfooconfig.yaml" \
  --output "${REPO_ROOT}/examples/promptfoo/outputs/promptfoo_results.json" \
  --output "${REPO_ROOT}/examples/promptfoo/outputs/promptfoo_summary.html" \
  --no-table \
  --no-progress-bar || true

echo "Generating SARIF report from Promptfoo results..."
if [ -f "${REPO_ROOT}/.venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/.venv/bin/activate"
fi

python3 "${REPO_ROOT}/scripts/promptfoo_to_sarif.py" \
  "${REPO_ROOT}/examples/promptfoo/outputs/promptfoo_results.json" \
  "${REPO_ROOT}/examples/promptfoo/outputs/promptfoo_report.sarif"

echo "Promptfoo execution completed. Generated artifacts in examples/promptfoo/outputs/"
