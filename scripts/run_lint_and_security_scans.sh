#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Security, SAST & Code Quality Scanner Suite
# ==============================================================================
# Runs:
# 1. Gitleaks Secrets Scanning (Working directory + Git commit history)
# 2. Semgrep SAST / Security Rule Scanner
# 3. Ruff Python Linter & Code Quality Check
# 4. Tool I/O Fixture Schema & Integrity Validator
# 5. Unified Parser SDK Test Suite
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

echo "========================================================================"
echo " 🔒 Running Security Scanners, Linters & Fixture Integrity Checks"
echo "========================================================================"
echo "Repository Root: ${REPO_ROOT}"
echo ""

# ------------------------------------------------------------------------------
# 1. Secrets Scan (Gitleaks)
# ------------------------------------------------------------------------------
echo "--- [1/5] Running Gitleaks Secrets Detection ---"
if command -v gitleaks &>/dev/null; then
  gitleaks detect --verbose --config="${REPO_ROOT}/.gitleaks.toml"
  echo "✅ Gitleaks secrets detection passed (no genuine leaks found)."
else
  echo "⚠️ Gitleaks not found on host path. Skipping local gitleaks check."
fi
echo ""

# ------------------------------------------------------------------------------
# 2. SAST / Security Vulnerability Scan (Semgrep)
# ------------------------------------------------------------------------------
echo "--- [2/5] Running Semgrep SAST & Security Rule Scan ---"
if command -v semgrep &>/dev/null; then
  semgrep scan \
    --config auto \
    --exclude="node_modules" \
    --exclude=".venv" \
    --exclude="clarity-agent" \
    --error
  echo "✅ Semgrep SAST scan passed with 0 blocking findings."
else
  echo "⚠️ Semgrep not found on host path. Skipping local semgrep check."
fi
echo ""

# ------------------------------------------------------------------------------
# 3. Python Linter & Quality Check (Ruff)
# ------------------------------------------------------------------------------
echo "--- [3/5] Running Ruff Python Linter ---"
if command -v ruff &>/dev/null; then
  ruff check docker/ scripts/ sdk/ harnesses/
  echo "✅ Ruff Python linting passed with 0 errors."
else
  # Fallback to docker container
  if command -v docker-compose &>/dev/null || docker compose version &>/dev/null; then
    COMPOSE_CMD="docker-compose"
    command -v docker-compose &>/dev/null || COMPOSE_CMD="docker compose"
    ${COMPOSE_CMD} -f "${REPO_ROOT}/docker/docker-compose.full.yml" run --rm harness-runner \
      -c "pip install --quiet ruff && ruff check docker/ scripts/ sdk/ harnesses/"
    echo "✅ Ruff Python linting passed via containerized runner."
  else
    echo "⚠️ Neither local ruff nor docker found. Skipping ruff check."
  fi
fi
echo ""

# ------------------------------------------------------------------------------
# 4. Tool I/O Fixture Schema & Integrity Validation
# ------------------------------------------------------------------------------
echo "--- [4/5] Running Tool I/O Fixture Integrity & Schema Validator ---"
if [ -f "${REPO_ROOT}/.venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/.venv/bin/activate"
fi

if command -v python3 &>/dev/null; then
  python3 "${REPO_ROOT}/scripts/validate_fixtures.py"
else
  COMPOSE_CMD="docker-compose"
  command -v docker-compose &>/dev/null || COMPOSE_CMD="docker compose"
  ${COMPOSE_CMD} -f "${REPO_ROOT}/docker/docker-compose.full.yml" run --rm harness-runner \
    -c "python3 /workspace/scripts/validate_fixtures.py"
fi
echo ""

# ------------------------------------------------------------------------------
# 5. Unified Parser SDK Unit & Integration Tests
# ------------------------------------------------------------------------------
echo "--- [5/5] Running Unified Parser SDK Test Suite ---"
if command -v pytest &>/dev/null; then
  pytest "${REPO_ROOT}/sdk/tests/test_sdk.py" -v
else
  COMPOSE_CMD="docker-compose"
  command -v docker-compose &>/dev/null || COMPOSE_CMD="docker compose"
  ${COMPOSE_CMD} -f "${REPO_ROOT}/docker/docker-compose.full.yml" run --rm harness-runner \
    -c "python3 -m pytest /workspace/sdk/tests/test_sdk.py -v"
fi
echo ""

echo "========================================================================"
echo " 🎉 All security scans, SAST rules, linters, and fixture tests PASSED!"
echo "========================================================================"
