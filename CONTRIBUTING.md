# Contributing to Adversarial Testing Tool I/O Examples

Thank you for your interest in contributing! 🎉 

This project aims to be the open-source hub of **standardized, reproducible input and output (Tool I/O) datasets, execution harnesses, and offline mock targets** for LLM red-teaming, safety benchmarking, and adversarial robustness tools.

Whether you are fixing a typo, adding a new AI safety tool adapter, expanding attack probe catalogs, or building converters for downstream security tools, your contribution is warmly welcomed.

---

## 🧭 Ways to Contribute

There are many ways you can help:

1. **Add a New Tool Adapter:** Build a harness and mock integration for an adversarial testing tool not yet covered (e.g., **Inspect AI**, **DeepEval**, **Meta CyberSecEval**, **Giskard**, **AutoDAN**, **NeMo Guardrails**, **Mindgard**).
2. **Contribute Attack Probes & Scenarios:** Expand `examples/*/inputs/` with realistic, safe test cases (e.g., multi-turn jailbreaks, MCP sandbox escapes, cross-prompt injection (XPIA), tool call parameter poisoning).
3. **Build Output Converters & Visualizers:** Create utilities that convert raw tool outputs into universal formats like **SARIF 2.1.0**, **CycloneDX 1.6**, **DefectDojo**, or **OpenTelemetry traces**.
4. **Improve Mock Environments:** Enhance our FastAPI mock LLM API and mock MCP server in `docker/` to simulate more real-world model behaviors, errors, and tool-call signatures.
5. **Documentation & Validation:** Improve schema definitions, write tutorials, or strengthen `scripts/validate_fixtures.py`.

---

## 🛠️ Local Development Setup

### 1. Prerequisites
- **Git**
- **Python 3.11+**
- **Node.js 18+** & npm
- **Docker & Docker Compose** (Docker Desktop, Colima, or OrbStack)

### 2. Fork and Clone
```bash
git clone https://github.com/<your-username>/adversarial_testing_tool_io_examples.git
cd adversarial_testing_tool_io_examples
git checkout -b feat/my-new-contribution
```

### 3. Initialize Virtual Environments
```bash
# Python setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Node.js setup
npm install
```

### 4. Verify Local Mocks
Start the mock environment and verify the health endpoints:
```bash
docker compose -f docker/docker-compose.yml up -d
curl http://localhost:8000/health
# Response: {"status":"healthy","service":"mock-llm-api"}
docker compose -f docker/docker-compose.yml down
```

---

## 📐 Guidelines for Adding a New Tool Harness

When adding support for a new testing tool (e.g. `<tool_name>`):

1. **Directory Structure:**
   - Create `harnesses/<tool_name>/`: Contains runnable harness script (`run.sh`) and any harness-specific configs.
   - Create `examples/<tool_name>/inputs/`: Checked-in input configurations, attack catalogs, or test definitions.
   - Create `examples/<tool_name>/outputs/`: Authentic output artifacts produced by running against the mock target.

2. **Offline & Zero-Cost Requirement:**
   - The harness **must execute entirely offline against the local Docker mock environment** (`http://localhost:8000` or `http://localhost:8001`).
   - Do **NOT** require paid cloud API keys or live external network connections.
   - Keep execution time fast (ideally `< 30 seconds`).

3. **Sanitize Data:**
   - Never commit API keys, personal names, internal tokens, or proprietary system prompts.
   - Ensure file paths in checked-in outputs use relative or mock paths.

4. **Add to Fixture Validator:**
   - Update `scripts/validate_fixtures.py` to register the expected input and output files for the new tool.
   - Run the validator to confirm everything passes:
     ```bash
     python3 scripts/validate_fixtures.py
     ```

5. **Update Documentation:**
   - Add the tool to the table in `README.md`.
   - Update `docs/TOOL_IO_SPECIFICATION.md` detailing the file formats and schemas.

---

## 📋 Pull Request Process

1. **Ensure All Harnesses and Validators Pass:**
   ```bash
   ./scripts/run_all_harnesses.sh --down
   ```
2. **Commit with Conventional Commits:**
   Use clear, conventional commit messages:
   - `feat(harness): add Inspect AI evaluation harness`
   - `fix(mock): support streaming tokens in mock-llm-api`
   - `docs: update tool comparison matrix in README`
   - `test(validator): check SARIF 2.1.0 schema validity`
3. **Submit Your PR:**
   - Push your branch to your GitHub fork:
     ```bash
     git push origin feat/my-new-contribution
     ```
   - Open a Pull Request against `master` on `sodejm/adversarial_testing_tool_io_examples`.
   - Describe what tool, probe, or feature was added and include sample output excerpts where relevant.

---

## 🛡️ Responsible Security & Safety Notice

All prompts, configurations, and outputs in this repository are created solely for **defensive security evaluation, AI vulnerability research, and software test fixtures**. Do not submit actionable malicious exploits targeted against live production systems.

---

Thank you for helping make generative AI and autonomous agents safer and more robust! 🚀
