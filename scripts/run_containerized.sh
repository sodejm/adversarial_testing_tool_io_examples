#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Containerized Runner: Adversarial Testing Tool I/O Harnesses
# ==============================================================================
# Executes all harnesses inside a self-contained multi-runtime Docker container
# with zero host dependencies (no host Python or Node.js required).
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker/docker-compose.full.yml"

BUILD_FLAG=""
CLEAN_ONLY=false
HARNESS_MODE="--parallel"

for arg in "$@"; do
  case $arg in
    --build)
      BUILD_FLAG="--build"
      ;;
    --clean)
      CLEAN_ONLY=true
      ;;
    --sequential)
      HARNESS_MODE="--sequential"
      ;;
    --parallel)
      HARNESS_MODE="--parallel"
      ;;
    --docker)
      # Handled when invoked via run_all_harnesses.sh --docker
      ;;
    -h|--help)
      echo "Usage: $0 [--build] [--parallel | --sequential] [--clean]"
      echo "  --build        Force rebuild of the harness runner image"
      echo "  --parallel     Run all 6 harnesses in parallel (default)"
      echo "  --sequential   Run harnesses sequentially"
      echo "  --clean        Tear down containers and remove volumes"
      exit 0
      ;;
  esac
done

# Detect docker compose
if command -v docker-compose &>/dev/null; then
  DOCKER_COMPOSE="docker-compose"
elif docker compose version &>/dev/null; then
  DOCKER_COMPOSE="docker compose"
else
  echo "Error: Neither 'docker compose' nor 'docker-compose' found. Please install Docker." >&2
  exit 1
fi

if [ "${CLEAN_ONLY}" = true ]; then
  echo "Cleaning up containerized environment..."
  ${DOCKER_COMPOSE} -f "${COMPOSE_FILE}" down -v --remove-orphans
  echo "Cleanup complete."
  exit 0
fi

echo "========================================================================"
echo " Launching Containerized Adversarial Testing Harness Runner"
echo "========================================================================"
echo "Compose File:   ${COMPOSE_FILE}"
echo "Harness Mode:   ${HARNESS_MODE}"
echo "Build Flag:     ${BUILD_FLAG:-none (using cache)}"
echo ""

cleanup() {
  echo ""
  echo "Tearing down containerized services..."
  ${DOCKER_COMPOSE} -f "${COMPOSE_FILE}" down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT INT TERM

export HARNESS_MODE

${DOCKER_COMPOSE} -f "${COMPOSE_FILE}" up \
  ${BUILD_FLAG} \
  --abort-on-container-exit \
  --exit-code-from harness-runner

echo ""
echo "========================================================================"
echo " Containerized execution completed successfully!"
echo " All Tool I/O fixtures generated in examples/ and validated."
echo "========================================================================"
