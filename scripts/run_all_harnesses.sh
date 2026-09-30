#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Master Orchestration Script: Adversarial Testing Tool I/O Harnesses
# ==============================================================================
# Spins up local mock environments, sequentially runs all harnesses:
# 1. Promptfoo (OWASP Top 10, MCP Prompt Injection, Auth Bypass)
# 2. PyRIT (Single-turn, Converters, Memory DB, Crescendo Jailbreak)
# 3. Garak (PromptInject, DAN, Encoding, XSS, LeakReplay probes)
# 4. RAMPART (Agentic red-teaming, Tool Auth Bypass, Indirect Injection, Data Leakage)
#
# Finally runs validation against all generated artifacts.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DOWN_ON_FINISH=false
for arg in "$@"; do
  case $arg in
    --down)
      DOWN_ON_FINISH=true
      shift
      ;;
  esac
done

# Detect docker-compose command
if command -v docker-compose &>/dev/null; then
  DOCKER_COMPOSE="docker-compose"
elif docker compose version &>/dev/null; then
  DOCKER_COMPOSE="docker compose"
else
  echo "Error: Neither 'docker-compose' nor 'docker compose' found on PATH." >&2
  exit 1
fi

echo "========================================================================"
echo " Starting Master Adversarial Testing Orchestrator"
echo "========================================================================"
echo "Docker Compose Engine: ${DOCKER_COMPOSE}"
echo "Repository Root:       ${REPO_ROOT}"

# Teardown handler if requested
cleanup() {
  if [ "${DOWN_ON_FINISH}" = true ]; then
    echo ""
    echo "Tearing down mock Docker environment..."
    ${DOCKER_COMPOSE} -f "${REPO_ROOT}/docker/docker-compose.yml" down
  fi
}
trap cleanup EXIT

# 1. Start Docker Mock Services
echo ""
echo "[1/6] Launching local mock target environment..."
${DOCKER_COMPOSE} -f "${REPO_ROOT}/docker/docker-compose.yml" up -d

echo "Waiting for services to become healthy..."
RETRIES=30
until curl -s http://localhost:8000/health >/dev/null && curl -s http://localhost:8001/health >/dev/null; do
  RETRIES=$((RETRIES - 1))
  if [ $RETRIES -le 0 ]; then
    echo "Error: Mock environments failed to become healthy within 30 seconds." >&2
    ${DOCKER_COMPOSE} -f "${REPO_ROOT}/docker/docker-compose.yml" logs
    exit 1
  fi
  sleep 1
done
echo "Mock targets ready:"
echo " - Mock LLM API:    http://localhost:8000/v1"
echo " - Mock MCP Server: http://localhost:8001/mcp"

# 2. Run Promptfoo Harness
echo ""
echo "[2/6] Executing Promptfoo Harness..."
bash "${REPO_ROOT}/harnesses/promptfoo/run.sh"

# 3. Run PyRIT Harness
echo ""
echo "[3/6] Executing PyRIT Harness..."
bash "${REPO_ROOT}/harnesses/pyrit/run.sh"

# 4. Run Garak Harness
echo ""
echo "[4/6] Executing Garak Probing Harness..."
bash "${REPO_ROOT}/harnesses/garak/run.sh"

# 5. Run RAMPART Harness
echo ""
echo "[5/6] Executing RAMPART Agentic Safety Harness..."
bash "${REPO_ROOT}/harnesses/rampart/run.sh"

# 6. Validate All Generated Fixtures
echo ""
echo "[6/6] Validating All Generated Tool I/O Fixtures..."
if [ -f "${REPO_ROOT}/.venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/.venv/bin/activate"
fi

python3 "${REPO_ROOT}/scripts/validate_fixtures.py"

echo ""
echo "========================================================================"
echo " All harnesses completed and all Tool I/O artifacts successfully frozen!"
echo "========================================================================"
