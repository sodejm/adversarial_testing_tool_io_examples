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

PARALLEL_MODE=true
DOWN_ON_FINISH=false
SKIP_DOCKER=false

for arg in "$@"; do
  case $arg in
    --down)
      DOWN_ON_FINISH=true
      ;;
    --skip-docker)
      SKIP_DOCKER=true
      ;;
    --sequential)
      PARALLEL_MODE=false
      ;;
    --parallel)
      PARALLEL_MODE=true
      ;;
    -h|--help)
      echo "Usage: $0 [--parallel | --sequential] [--down] [--skip-docker]"
      echo "  --parallel     Run all 6 harnesses concurrently (default, fastest)"
      echo "  --sequential   Run harnesses sequentially one after another"
      echo "  --down         Tear down docker mock containers when complete"
      echo "  --skip-docker  Skip starting/stopping Docker containers (targets assumed running)"
      exit 0
      ;;
  esac
done

LLM_HEALTH_URL="${MOCK_LLM_HEALTH_URL:-http://localhost:8000/health}"
MCP_HEALTH_URL="${MOCK_MCP_HEALTH_URL:-http://localhost:8001/health}"

# Detect docker-compose command if docker not skipped
DOCKER_COMPOSE=""
if [ "${SKIP_DOCKER}" = false ]; then
  if command -v docker-compose &>/dev/null; then
    DOCKER_COMPOSE="docker-compose"
  elif docker compose version &>/dev/null; then
    DOCKER_COMPOSE="docker compose"
  fi
fi

echo "========================================================================"
echo " Starting Master Adversarial Testing Orchestrator"
echo "========================================================================"
echo "Docker Compose Engine: ${DOCKER_COMPOSE:-none (skipped or unavailable)}"
echo "Repository Root:       ${REPO_ROOT}"
echo "Execution Mode:        $([ "${PARALLEL_MODE}" = true ] && echo "Parallel (Fastest)" || echo "Sequential")"

# Teardown handler
cleanup() {
  local jobs_list
  jobs_list=$(jobs -p) || true
  if [ -n "${jobs_list}" ]; then
    kill ${jobs_list} 2>/dev/null || true
  fi
  if [ "${DOWN_ON_FINISH}" = true ] && [ "${SKIP_DOCKER}" = false ] && [ -n "${DOCKER_COMPOSE}" ]; then
    echo ""
    echo "Tearing down mock Docker environment..."
    ${DOCKER_COMPOSE} -f "${REPO_ROOT}/docker/docker-compose.yml" down
  fi
}
trap cleanup EXIT INT TERM

# 1. Start Docker Mock Services
if [ "${SKIP_DOCKER}" = true ]; then
  echo ""
  echo "[1/3] Skipping Docker startup (--skip-docker specified)..."
elif curl -s "${LLM_HEALTH_URL}" >/dev/null && curl -s "${MCP_HEALTH_URL}" >/dev/null; then
  echo ""
  echo "[1/3] Mock target services already running and healthy."
elif [ -n "${DOCKER_COMPOSE}" ]; then
  echo ""
  echo "[1/3] Launching local mock target environment..."
  ${DOCKER_COMPOSE} -f "${REPO_ROOT}/docker/docker-compose.yml" up -d
else
  echo ""
  echo "[1/3] Checking connectivity to external mock services..."
fi

echo "Verifying mock services are healthy..."
RETRIES=120
until curl -s "${LLM_HEALTH_URL}" >/dev/null && curl -s "${MCP_HEALTH_URL}" >/dev/null; do
  RETRIES=$((RETRIES - 1))
  if [ $RETRIES -le 0 ]; then
    echo "Error: Mock environments failed to become healthy within 30 seconds." >&2
    if [ -n "${DOCKER_COMPOSE}" ] && [ "${SKIP_DOCKER}" = false ]; then
      ${DOCKER_COMPOSE} -f "${REPO_ROOT}/docker/docker-compose.yml" logs
    fi
    exit 1
  fi
  sleep 0.25
done
echo "Mock targets ready:"
echo " - Mock LLM Health:  ${LLM_HEALTH_URL}"
echo " - Mock MCP Health:  ${MCP_HEALTH_URL}"

# 2. Run Harnesses
if [ "${PARALLEL_MODE}" = true ]; then
  echo ""
  echo "[2/3] Executing all 6 harnesses in parallel (Promptfoo, PyRIT, Garak, RAMPART, Inspect AI, DeepTeam)..."
  LOGS_DIR="${REPO_ROOT}/.logs"
  mkdir -p "${LOGS_DIR}"

  START_TIME=$(date +%s)

  bash "${REPO_ROOT}/harnesses/promptfoo/run.sh" > "${LOGS_DIR}/promptfoo.log" 2>&1 &
  PID_PROMPTFOO=$!

  bash "${REPO_ROOT}/harnesses/pyrit/run.sh" > "${LOGS_DIR}/pyrit.log" 2>&1 &
  PID_PYRIT=$!

  bash "${REPO_ROOT}/harnesses/garak/run.sh" > "${LOGS_DIR}/garak.log" 2>&1 &
  PID_GARAK=$!

  bash "${REPO_ROOT}/harnesses/rampart/run.sh" > "${LOGS_DIR}/rampart.log" 2>&1 &
  PID_RAMPART=$!

  bash "${REPO_ROOT}/harnesses/inspect_ai/run.sh" > "${LOGS_DIR}/inspect_ai.log" 2>&1 &
  PID_INSPECT=$!

  bash "${REPO_ROOT}/harnesses/deepteam/run.sh" > "${LOGS_DIR}/deepteam.log" 2>&1 &
  PID_DEEPTEAM=$!

  FAILED=false

  # Wait for Promptfoo
  if wait "${PID_PROMPTFOO}"; then
    echo "  ✅ [Promptfoo] Harness completed successfully."
  else
    echo "  ❌ [Promptfoo] Harness failed! Check ${LOGS_DIR}/promptfoo.log" >&2
    cat "${LOGS_DIR}/promptfoo.log" >&2
    FAILED=true
  fi

  # Wait for PyRIT
  if wait "${PID_PYRIT}"; then
    echo "  ✅ [PyRIT] Harness completed successfully."
  else
    echo "  ❌ [PyRIT] Harness failed! Check ${LOGS_DIR}/pyrit.log" >&2
    cat "${LOGS_DIR}/pyrit.log" >&2
    FAILED=true
  fi

  # Wait for Garak
  if wait "${PID_GARAK}"; then
    echo "  ✅ [Garak] Harness completed successfully."
  else
    echo "  ❌ [Garak] Harness failed! Check ${LOGS_DIR}/garak.log" >&2
    cat "${LOGS_DIR}/garak.log" >&2
    FAILED=true
  fi

  # Wait for RAMPART
  if wait "${PID_RAMPART}"; then
    echo "  ✅ [RAMPART] Harness completed successfully."
  else
    echo "  ❌ [RAMPART] Harness failed! Check ${LOGS_DIR}/rampart.log" >&2
    cat "${LOGS_DIR}/rampart.log" >&2
    FAILED=true
  fi

  # Wait for Inspect AI
  if wait "${PID_INSPECT}"; then
    echo "  ✅ [Inspect AI] Harness completed successfully."
  else
    echo "  ❌ [Inspect AI] Harness failed! Check ${LOGS_DIR}/inspect_ai.log" >&2
    cat "${LOGS_DIR}/inspect_ai.log" >&2
    FAILED=true
  fi

  # Wait for DeepTeam
  if wait "${PID_DEEPTEAM}"; then
    echo "  ✅ [DeepTeam] Harness completed successfully."
  else
    echo "  ❌ [DeepTeam] Harness failed! Check ${LOGS_DIR}/deepteam.log" >&2
    cat "${LOGS_DIR}/deepteam.log" >&2
    FAILED=true
  fi

  if [ "${FAILED}" = true ]; then
    echo "Error: One or more harnesses failed during parallel execution." >&2
    exit 1
  fi

  ELAPSED=$(( $(date +%s) - START_TIME ))
  echo "All 6 harnesses finished concurrently in ~${ELAPSED}s."

else
  # Sequential mode
  echo ""
  echo "[2/7] Executing Promptfoo Harness..."
  bash "${REPO_ROOT}/harnesses/promptfoo/run.sh"

  echo ""
  echo "[3/7] Executing PyRIT Harness..."
  bash "${REPO_ROOT}/harnesses/pyrit/run.sh"

  echo ""
  echo "[4/7] Executing Garak Probing Harness..."
  bash "${REPO_ROOT}/harnesses/garak/run.sh"

  echo ""
  echo "[5/7] Executing RAMPART Agentic Safety Harness..."
  bash "${REPO_ROOT}/harnesses/rampart/run.sh"

  echo ""
  echo "[6/7] Executing Inspect AI Harness..."
  bash "${REPO_ROOT}/harnesses/inspect_ai/run.sh"

  echo ""
  echo "[7/7] Executing DeepTeam Harness..."
  bash "${REPO_ROOT}/harnesses/deepteam/run.sh"
fi

# 3. Validate All Generated Fixtures
echo ""
echo "[3/3] Validating All Generated Tool I/O Fixtures..."
if [ -f "${REPO_ROOT}/.venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/.venv/bin/activate"
fi

python3 "${REPO_ROOT}/scripts/validate_fixtures.py"

echo ""
echo "========================================================================"
echo " All harnesses completed and all Tool I/O artifacts successfully frozen!"
echo "========================================================================"
