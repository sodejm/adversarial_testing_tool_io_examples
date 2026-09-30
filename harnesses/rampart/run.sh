#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Running RAMPART Agentic Safety Testing Harness ==="

export RAMPART_TARGET_LLM_URL="${RAMPART_TARGET_LLM_URL:-http://localhost:8000/v1}"
export RAMPART_TARGET_MCP_URL="${RAMPART_TARGET_MCP_URL:-http://localhost:8001/mcp}"
export RAMPART_INPUT_DIR="${REPO_ROOT}/examples/rampart/inputs"
export RAMPART_OUTPUT_DIR="${REPO_ROOT}/examples/rampart/outputs"

mkdir -p "${RAMPART_INPUT_DIR}"
mkdir -p "${RAMPART_OUTPUT_DIR}"

# Copy input test suite specification
cp "${SCRIPT_DIR}/test_agentic_safety.py" "${RAMPART_INPUT_DIR}/test_agentic_safety.py"
echo "Copied test specification to: ${RAMPART_INPUT_DIR}/test_agentic_safety.py"

if [ -f "${REPO_ROOT}/.venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/.venv/bin/activate"
fi

cd "${SCRIPT_DIR}"

echo "Executing RAMPART pytest suite..."
python3 -m pytest "${SCRIPT_DIR}/test_agentic_safety.py" \
  -v \
  --junitxml="${RAMPART_OUTPUT_DIR}/rampart_results.xml" || true

echo "RAMPART execution completed. Generated artifacts in examples/rampart/outputs/"
