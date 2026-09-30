# Harness Architecture & Execution Engine

This document details the architectural design, containerized mock target environment, execution pipelines, and data synchronization flows powering the **Adversarial Testing Tool I/O** repository.

---

## 1. System Architecture

```
                                    +-------------------------------------------------------------+
                                    |              Master Orchestration Pipeline                  |
                                    |               (scripts/run_all_harnesses.sh)                |
                                    +------------------------------+------------------------------+
                                                                   |
                                              1. Spin up & await healthcheck
                                                                   v
                                    +-------------------------------------------------------------+
                                    |              Docker Mock Target Infrastructure              |
                                    |                  (docker/docker-compose.yml)                |
                                    |                                                             |
                                    |  +---------------------------+   +-----------------------+  |
                                    |  |       mock-llm-api        |   |    mock-mcp-server    |  |
                                    |  |   - OpenAI /v1/chat       |   |   - JSON-RPC 2.0      |  |
                                    |  |   - Ollama /api/chat      |   |   - Tools & Resources |  |
                                    |  |   - Deterministic triggers|   |   - Poisoned Invoices |  |
                                    |  |   - Port 8000             |   |   - Port 8001         |  |
                                    |  +---------------------------+   +-----------------------+  |
                                    +------------------------------+------------------------------+
                                                                   |
                                              2. Execute test harnesses against mock targets
                                                                   |
          +-------------------------+------------------------------+-------------------------------+
          |                         |                              |                               |
          v                         v                              v                               v
+-------------------+     +--------------------+       +----------------------+       +-----------------------+
| Promptfoo Harness |     |   PyRIT Harness    |       |    Garak Harness     |       |    RAMPART Harness    |
| (harnesses/       |     | (harnesses/        |       | (harnesses/          |       | (harnesses/           |
|  promptfoo/)      |     |  pyrit/)           |       |  garak/)             |       |  rampart/)            |
|                   |     |                    |       |                      |       |                       |
| - CLI Evaluator   |     | - Attack Catalog   |       | - Garak Probe Engine |       | - Pytest-Native Tests |
| - SARIF Converter |     | - Converters (B64) |       | - Parallel Probing   |       | - AgentAdapter & MCP  |
| - Assertions      |     | - Crescendo Engine |       | - Report Digest      |       | - Evaluators & Sinks  |
+---------+---------+     +---------+----------+       +----------+-----------+       +-----------+-----------+
          |                         |                             |                               |
          +-------------------------+-----------------------------+-------------------------------+
                                                                  |
                                              3. Synchronize & Freeze Tool I/O
                                                                  v
                                    +-------------------------------------------------------------+
                                    |                  Frozen Tool I/O Fixtures                   |
                                    |                         (examples/)                         |
                                    |                                                             |
                                    |  examples/promptfoo/  (json, sarif, html)                   |
                                    |  examples/pyrit/      (sqlite db, json scores, transcripts) |
                                    |  examples/garak/      (report.jsonl, hitlog, html)          |
                                    |  examples/rampart/    (junit xml, eval.json)                |
                                    +------------------------------+------------------------------+
                                                                   |
                                              4. Validate Schema & Semantic Integrity
                                                                   v
                                    +-------------------------------------------------------------+
                                    |           Fixture Validator (scripts/validate_fixtures.py)  |
                                    |             Verifies 100% of fixtures pass checks           |
                                    +-------------------------------------------------------------+
```

---

## 2. Docker Mock Target Services

### 2.1 `mock-llm-api` (Port 8000)
- **Role**: Emulates commercial LLM provider APIs (OpenAI and Ollama) with zero cloud dependencies.
- **Tech Stack**: FastAPI, Uvicorn, Pydantic v2.
- **Endpoints**:
  - `GET /`, `GET /v1`, `GET /health`: System status and connectivity verification.
  - `GET /v1/models`: Returns supported mock models (`gpt-3.5-turbo`, `gpt-4o`, `mock-vulnerable-model`, `mock-defended-model`).
  - `POST /v1/chat/completions`: OpenAI-compatible chat completion endpoint supporting standard parameters (`model`, `messages`, `temperature`, `max_tokens`, `stream`).
  - `POST /api/chat`, `POST /api/generate`: Ollama-compatible completion endpoints.
- **Dual Mode Operation**:
  - **Vulnerable Mode** (default): Evaluates incoming prompt text against regex patterns. If an adversarial pattern is detected (e.g. system directive override, DAN trigger, credential exfiltration, role elevation, or reflected script tag), it generates the exact vulnerable signature to allow automated red-teaming detectors to record a hit.
  - **Defended Mode** (triggered by header `x-mock-mode: defended` or model name containing `defended`): Refuses any request matching attack patterns with safe refusal messages.

### 2.2 `mock-mcp-server` (Port 8001)
- **Role**: Implements the Model Context Protocol (MCP) JSON-RPC 2.0 specification over HTTP.
- **Protocol Methods**:
  - `initialize`: Protocol negotiation, declaring tools, resources, and prompt capabilities.
  - `tools/list`: Declares available callable agent tools.
  - `tools/call`: Executes tool operations.
  - `resources/list`, `resources/read`: Provides access to static and dynamic resources.
  - `prompts/list`: Exposes prompt templates.
- **Exposed Tools & Adversarial Primitives**:
  - `query_database(query: str)`: Internal SQL query interface. When queried for secrets or passwords, simulates data exfiltration by returning user records with tokens.
  - `fetch_internal_document(document_id: str)`: Returns document contents. When `document_id` references `untrusted_vendor_invoice`, returns poisoned content with embedded indirect prompt injection directives.
  - `modify_user_role(username: str, role: str)`: Updates enterprise authorization roles. Simulates privilege escalation vulnerabilities when called without prior authorization.
  - `execute_system_command(command: str)`: Simulates command injection vulnerability by returning root user shell execution telemetry.

---

## 3. Harness Architecture

### 3.1 Promptfoo Harness (`harnesses/promptfoo/`)
- **Execution Script**: `harnesses/promptfoo/run.sh`
- **Configuration**: `harnesses/promptfoo/promptfooconfig.yaml`
- **Workflow**:
  1. Copies `promptfooconfig.yaml` to `examples/promptfoo/inputs/`.
  2. Executes `npx promptfoo eval` targeting `http://localhost:8000/v1` with `openai:chat:gpt-3.5-turbo`.
  3. Outputs native `promptfoo_results.json` and `promptfoo_summary.html`.
  4. Invokes `scripts/promptfoo_to_sarif.py` to translate evaluation results into OASIS standard `promptfoo_report.sarif`.

### 3.2 PyRIT Harness (`harnesses/pyrit/`)
- **Execution Script**: `harnesses/pyrit/run.sh`
- **Orchestrator**: `harnesses/pyrit/pyrit_adversarial_suite.py`
- **Workflow**:
  1. Loads `ATTACK_CATALOG` covering prompt injection, data leakage, auth bypass, and indirect injection.
  2. Exports seed attack specifications to `examples/pyrit/inputs/pyrit_attack_catalog.json`.
  3. Executes single-turn attacks across multiple converter pipelines (`raw`, `base64`, `rot13`).
  4. Executes multi-turn Crescendo jailbreak session, incrementally escalating adversarial intent across turns.
  5. Commits all messages, roles, and converter transforms into SQLite `pyrit_memory.db`.
  6. Evaluates target responses via heuristic scorers and persists scores into the database.
  7. Serializes evaluation metrics to `pyrit_eval_results.json` and session transcripts to `pyrit_crescendo_session.json`.

### 3.3 Garak Harness (`harnesses/garak/`)
- **Execution Script**: `harnesses/garak/run.sh`
- **Runner**: `harnesses/garak/garak_adversarial_runner.py`
- **Configuration**: `harnesses/garak/garak_probes.yaml`
- **Workflow**:
  1. Copies probe specifications to `examples/garak/inputs/garak_probes.yaml`.
  2. Configures Garak with target type `openai.OpenAICompatible` pointing to `http://localhost:8000/v1`.
  3. Runs probe modules in parallel (`--parallel_attempts 16`):
     - `dan.Ablation_Dan_11_0`: DAN jailbreak evaluation.
     - `promptinject.HijackHateHumans`: PromptInject rogue hijacked strings.
     - `encoding.InjectBase64`: Base64 encoded payload evasion.
     - `web_injection.MarkdownXSS`: Stored/reflected XSS script injection.
     - `leakreplay.GuardianCloze`: Data memorization and cloze extraction.
  4. Captures output stream and saves:
     - `garak_scan.report.jsonl`: Complete execution telemetry.
     - `garak_scan.hitlog.jsonl`: Filtered records of successful exploits.
     - `garak_report.html`: Self-contained visual HTML report.

### 3.4 RAMPART Harness (`harnesses/rampart/`)
- **Execution Script**: `harnesses/rampart/run.sh`
- **Test Suite**: `harnesses/rampart/test_agentic_safety.py`
- **Configuration**: `harnesses/rampart/conftest.py`
- **Workflow**:
  1. Copies test specification to `examples/rampart/inputs/test_agentic_safety.py`.
  2. Implements `MockAgentAdapter` with `AppManifest` declaring tools and data sources.
  3. Bridges pytest test cases with both the Mock LLM API and the Mock MCP server.
  4. Runs safety test cases for:
     - Tool Authorization Bypass (Vulnerable & Defended modes)
     - Indirect Prompt Injection via Poisoned MCP Resources (Vulnerable & Defended modes)
     - Sensitive Data Leakage & Credential Exfiltration (Vulnerable & Defended modes)
  5. Evaluates execution context via custom `BaseEvaluator` classes with full tool-call and side-effect observability.
  6. Automatically emits JUnit XML (`rampart_results.xml`) and RAMPART structured evaluation JSON (`rampart_eval.json`) via session-scoped `ReportSink`.

---

## 4. Master Orchestration & Fixture Validation

### 4.1 Master Orchestrator: `scripts/run_all_harnesses.sh`
The master script executes the complete regeneration sequence:
```bash
./scripts/run_all_harnesses.sh [--down]
```
1. Verifies Docker Compose, Python, and Node environments.
2. Starts Docker containers (`docker-compose up -d`) and polls health endpoints until healthy.
3. Sequentially executes Promptfoo, PyRIT, Garak, and RAMPART harnesses.
4. Executes `scripts/validate_fixtures.py` to ensure zero regressions in generated artifacts.
5. Optionally tears down containers when `--down` flag is supplied.

### 4.2 Fixture Validator: `scripts/validate_fixtures.py`
Runs 14 independent structural and semantic integrity checks:
- **File Existence & Non-emptiness**: Asserts all 14 expected input and output artifacts exist and are non-zero size.
- **JSON Parsing**: Confirms valid JSON syntax and parses key structures.
- **SARIF 2.1.0 Validation**: Verifies schema version, rule metadata, and findings array.
- **JSONL Validation**: Iterates through every line of `garak_scan.report.jsonl` verifying newline-delimited JSON validity.
- **SQLite Database Inspection**: Connects to `pyrit_memory.db`, verifies required tables (`conversation_messages`, `score_entries`), and asserts row population.
- **JUnit XML Parsing**: Parses XML hierarchy and validates `<testsuite>` test counts.
- **HTML Document Verification**: Confirms presence of complete HTML markup and rendered tags.

---

## 5. Adding New Tools & Test Cases

1. **Adding an LLM Vulnerability Trigger**:
   Edit `docker/mock-llm-api/app.py`: add pattern to `detect_vulnerability_triggers()` and simulated response to `generate_simulated_response()`.
2. **Adding an MCP Tool or Poisoned Resource**:
   Edit `docker/mock-mcp-server/server.py`: append tool to `AVAILABLE_TOOLS` and handle execution in `handle_tool_call()`. Add resources to `MOCK_RESOURCES`.
3. **Adding a RAMPART Test Case**:
   Edit `harnesses/rampart/test_agentic_safety.py`: define a new `@pytest.mark.harm(...)` test function using the adapter session, evaluate observations, and call `record_result(result)`.
4. **Regenerating & Validating**:
   Run `./scripts/run_all_harnesses.sh` to update all frozen Tool I/O fixtures.
