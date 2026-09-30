# 🛡️ Adversarial Testing Tool I/O Examples

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)](CONTRIBUTING.md)
[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-blue.svg?style=for-the-badge&logo=python)](requirements.txt)
[![Node.js Version](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg?style=for-the-badge&logo=node.js)](package.json)
[![Docker](https://img.shields.io/badge/Docker-Compose%20Ready-2496ED.svg?style=for-the-badge&logo=docker)](docker/docker-compose.yml)
[![Open Source](https://img.shields.io/badge/Open%20Source-Heart%20AI%20Safety-red.svg?style=for-the-badge)](https://github.com/sodejm/adversarial_testing_tool_io_examples)

**The open-source repository of real input & output (Tool I/O) datasets, reproducible harnesses, and offline mock environments for leading GenAI red-teaming, LLM vulnerability scanners, and agentic AI safety frameworks.**

[Explore Datasets](#-checked-in-tool-io-fixtures--datasets) • [Supported Tools](#-supported-frameworks--matrix) • [Architecture](#-architecture--data-flow) • [Quickstart](#-quickstart--local-reproduction) • [Contributing Guide](#-we-want-contributors-join-the-mission)

</div>

---

## 📌 What is This Project?

Building downstream AI security infrastructure—such as **security triage dashboards, unified SARIF viewers, IDE vulnerability plugins, CI/CD safety gates, compliance audit generators, or policy enforcement engines**—requires parsing and transforming complex outputs from adversarial testing tools.

However, running live adversarial testing frameworks during development introduces major obstacles:
- 💸 **API Expenses & Quotas:** Commercial LLM tokens cost money and hit strict rate limits.
- 🌐 **Cloud Flakiness:** Network timeouts and third-party API changes break local test suites.
- 🎲 **Non-Deterministic Outputs:** Probabilistic model responses prevent stable, reproducible unit test fixtures.
- ⚙️ **Heavy Tool Dependencies:** Setting up multiple complex testing frameworks just to inspect report schemas is tedious and error-prone.

**Adversarial Testing Tool I/O Examples** solves this by providing:
1. **Real, Frozen Tool I/O Datasets:** Authentic, checked-in execution inputs (probes, catalogs, configs) and raw outputs (SARIF 2.1.0, JSON reports, SQLite runs, JSONL hitlogs, HTML dashboards, JUnit XML).
2. **Zero-Cost Offline Docker Mock Targets:** Self-contained mock servers simulating OpenAI-compatible `/v1/chat/completions`, Ollama `/api/chat`, and Model Context Protocol (MCP) servers with deterministic responses.
3. **Turnkey Execution Harnesses:** Single-command scripts that execute each tool against local mocks to generate fresh, valid fixtures on demand.
4. **Standardized Specifications & Validators:** Built-in schema validation (`scripts/validate_fixtures.py`) ensuring all datasets adhere to strict contracts.

---

## 🚀 We Want Contributors! Join the Mission

We actively welcome contributions from **AI security researchers, red-teamers, software engineers, and student developers**! Whether you want to add a new adversarial tool, contribute real attack probes, or build format parsers, your help is appreciated.

### 🌟 High-Priority Areas for Contribution

| Category | Contribution Ideas | Good First Issue? |
| :--- | :--- | :---: |
| 🔌 **New Tool Adapters** | Add harnesses for **Inspect AI (UK AISI)**, **DeepEval**, **Meta CyberSecEval**, **Giskard**, **AutoDAN**, **Mindgard**, or **NeMo Guardrails** | ⭐ Yes |
| 🎯 **Attack Probes & Vectors** | Add tests for **Multi-turn Crescendo**, **MCP sandbox escapes**, **Indirect Prompt Injection (XPIA)**, **ASCII Smuggling**, and **Tool-Calling Hijacks** | ⭐ Yes |
| 🔄 **Converters & Parsers** | Write format converters to **CycloneDX 1.6 (BOM)**, **DefectDojo**, **OpenTelemetry gen_ai spans**, or **GitHub Code Scanning SARIF** | ⭐ Yes |
| 🐳 **Mock Environment Expansion** | Simulate additional model backends (Claude Messages API, Gemini API, vLLM / HuggingFace TGI) | Medium |
| 📚 **Documentation & Guides** | Expand fixture schema documentation, tutorials on integrating fixtures with CI/CD gates, or tool comparison writeups | ⭐ Yes |

👉 Check out [`CONTRIBUTING.md`](CONTRIBUTING.md) for our quickstart developer guide and PR process!

---

## 🔍 Supported Frameworks & Matrix

| Framework | Core Capabilities | Primary Attack Vectors / Focus | Checked-in Input Formats | Checked-in Output Formats |
| :--- | :--- | :--- | :--- | :--- |
| **[Promptfoo](https://www.promptfoo.dev/)** | Automated LLM evaluation, red-teaming, prompt injection scanning | OWASP LLM Top 10, jailbreaks, MCP tool injection, SSRF, system prompt extraction, CWE-89/78 | `YAML` configuration, test assertions | `JSON` report, `SARIF 2.1.0`, `HTML` summary |
| **[PyRIT (Microsoft)](https://microsoft.github.io/PyRIT)** | Python Risk Identification Toolkit for GenAI; multi-turn attack orchestration | Multi-turn Crescendo attacks, adversarial converters (Base64, Rot13), scoring engines, RAG poisoning | `JSON` attack catalogs, orchestrator specs | `SQLite` database (`pyrit_memory.db`), `JSON` scores |
| **[Garak (NVIDIA)](https://github.com/NVIDIA/garak)** | Generative AI vulnerability scanner & probe suite | Hallucination, jailbreaks, prompt injection, XSS in Markdown, package hallucination | `YAML` probe configs, CLI generator flags | `JSONL` reports, `JSONL` hitlogs, interactive `HTML` |
| **[RAMPART (Microsoft)](https://github.com/microsoft/RAMPART)** | Pytest-native continuous safety testing framework for agentic AI | Cross-Prompt Injection (XPIA), tool manipulation, agent data exfiltration, RCE breakout, Confused Deputy | `Python` pytest suites, agent adapters | `JSON` evaluation logs, `XML` JUnit test reports |
| **[Inspect AI (UK AISI)](https://inspect.ai-safety-institute.org.uk/)** | UK/US AI Safety Institute evaluation platform for frontier models and agents | Agentic safety, memory context poisoning (ASI06), code sandbox escapes (ASI05), confused deputy (ASI02) | `YAML` task specs, sample datasets | `.eval` archive container (Zip), JSON eval logs |
| **[DeepTeam (Confident AI)](https://github.com/confident-ai/deepeval)** | Red-teaming framework mapping attacks to OWASP Top 10, MITRE ATLAS, and NIST AI RMF | Multi-turn red-team attack trees, risk progression trees, vulnerability matrices | `YAML` configuration, scenario specs | Risk matrix `JSON`, attack tree `JSON`, scorecard `JSON` |
| **[Clarity Agent (Microsoft)](https://github.com/microsoft/clarity-agent)** | Structured AI architectural review, goal distillation, and failure analysis | Threat modeling, architectural failure mode analysis, protocol documentation | Markdown goal statements, failure templates | `.clarity-protocol/` Markdown review packets |

---

## 🏗️ Architecture & Data Flow

```
                      +------------------------------------------------+
                      |         Adversarial Testing Frameworks         |
                      |  Promptfoo  |  PyRIT  |  Garak  |  RAMPART     |
                      +-----------------------+------------------------+
                                              |
                                              | [Executes offline against mocks]
                                              v
      +--------------------------------------------------------------------------------+
      |                         Offline Docker Mock Targets                            |
      |                                                                                |
      |  +------------------------------------+   +---------------------------------+  |
      |  |     FastAPI Mock LLM API           |   |      Mock MCP Server            |  |
      |  |  • OpenAI `/v1/chat/completions`   |   |  • Simulated Tool Schemas       |  |
      |  |  • Ollama `/api/chat` & `/generate`|   |  • Injection Test Payloads      |  |
      |  |  • Deterministic response rules    |   |  • JSON-RPC (stdio / SSE)       |  |
      |  +------------------------------------+   +---------------------------------+  |
      +--------------------------------------------------------------------------------+
                                              |
                                              | [Captures Real Tool I/O]
                                              v
      +--------------------------------------------------------------------------------+
      |                          Checked-In Tool I/O Datasets                          |
      |                                                                                |
      |  examples/                                                                     |
      |  ├── promptfoo/   ──> Inputs: yaml             Outputs: json, sarif, html      |
      |  ├── pyrit/       ──> Inputs: catalog.json     Outputs: sqlite, json, session  |
      |  ├── garak/       ──> Inputs: probes.yaml      Outputs: jsonl, html            |
      |  ├── rampart/     ──> Inputs: pytest suite     Outputs: junit xml, eval json   |
      |  ├── inspect_ai/  ──> Inputs: task.yaml        Outputs: .eval zip, eval json   |
      |  └── deepteam/    ──> Inputs: config.yaml      Outputs: matrix, trees, scorecard|
      +--------------------------------------------------------------------------------+
                                              |
                                              | [Normalized via Unified Python SDK]
                                              v
      +--------------------------------------------------------------------------------+
      |                  Unified Downstream Parser SDK (adversarial_toolio)            |
      |  • Single Pydantic model for all findings across all 6 frameworks              |
      |  • Standardized severity, threat categories, and pass/fail states              |
      +--------------------------------------------------------------------------------+
                                              |
                                              | [Consumed by Downstream Tooling]
                                              v
      +--------------------------------------------------------------------------------+
      |                     Downstream Consumers & Applications                        |
      |  • Security Triage Dashboards   • Unified SARIF Ingestion Engines              |
      |  • CI/CD Security Gate Rules    • AI Governance & Compliance Auditors          |
      +--------------------------------------------------------------------------------+
```

---

## 📂 Checked-In Tool I/O Fixtures & Datasets

All 21 datasets are frozen, validated, and directly usable as test fixtures:

```
examples/
├── promptfoo/
│   ├── inputs/
│   │   └── promptfooconfig.yaml          # Evaluation matrix, targets, and adversarial assertions
│   └── outputs/
│       ├── promptfoo_results.json        # Raw structured evaluation outputs
│       ├── promptfoo_report.sarif        # Standard SARIF 2.1.0 output for GitHub Security tab
│       └── promptfoo_summary.html        # Interactive HTML dashboard
├── pyrit/
│   ├── inputs/
│   │   └── pyrit_attack_catalog.json     # Adversarial prompts, converters, and strategies
│   └── outputs/
│       ├── pyrit_crescendo_session.json  # Multi-turn adaptive jailbreak transcript
│       ├── pyrit_eval_results.json       # Scorer judgments, confidence, and metrics
│       └── pyrit_memory.db               # SQLite database capturing full PyRIT memory state
├── garak/
│   ├── inputs/
│   │   └── garak_probes.yaml             # Probe taxonomy (dan, encoding, injection, xss)
│   └── outputs/
│       ├── garak_scan.report.jsonl       # Full execution trace by probe & detector
│       ├── garak_scan.hitlog.jsonl       # Triggered vulnerability hits and payloads
│       └── garak_report.html             # Standalone NVIDIA Garak interactive report
├── rampart/
│   ├── inputs/
│   │   └── test_agentic_safety.py        # Pytest-native agent safety & XPIA test specifications
│   └── outputs/
│       ├── rampart_eval.json             # Structured agentic execution & tool assertion logs
│       └── rampart_results.xml           # Standard JUnit XML report for CI/CD pipelines
├── inspect_ai/
│   ├── inputs/
│   │   └── agent_safety_task.yaml        # Inspect AI task and dataset configuration
│   └── outputs/
│       ├── agent_safety_task.eval        # Authentic UK AISI .eval Zip bundle (JSON logs inside)
│       └── agent_safety_task.eval.json   # High-level evaluation summary and scoring metrics
└── deepteam/
    ├── inputs/
    │   └── deepteam_config.yaml          # DeepTeam / DeepEval scenario attack matrix config
    └── outputs/
        ├── deepteam_vulnerability_matrix.json  # OWASP/ATLAS/NIST risk mapping matrix
        ├── deepteam_attack_trees.json    # Iterative attack progression trees
        └── deepteam_risk_scorecard.json  # Executive safety scorecard and posture summary
```

---

## ⚡ Quickstart & Local Reproduction

### Prerequisites
- **Git**
- **Docker & Docker Compose** (Docker Desktop, OrbStack, or Colima)
- **Python 3.11+**
- **Node.js 18+** & npm

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/sodejm/adversarial_testing_tool_io_examples.git
cd adversarial_testing_tool_io_examples

# Set up local Python virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Install Node dependencies (Promptfoo)
npm install
```

### 2. Run All 6 Harnesses & Validate (Single Command)
This spins up the local mock targets, runs Promptfoo, PyRIT, Garak, RAMPART, Inspect AI, and DeepTeam in parallel (~16s), and validates all 21 generated datasets:
```bash
./scripts/run_all_harnesses.sh --parallel --down
```
> **Tip**: Pass `--sequential` if you wish to run harnesses one after another with verbose sequential console output.

### 3. Fully Containerized Execution (Zero Host Dependencies)
Don't want to install Node.js, Python, or tool packages on your host system? Run everything inside an isolated, multi-runtime Docker container:
```bash
# Option A: Single-command turnkey containerized runner
./scripts/run_containerized.sh

# Option B: Pass --docker to the master harness runner
./scripts/run_all_harnesses.sh --docker

# Option C: Direct Docker Compose execution
docker-compose -f docker/docker-compose.full.yml up --abort-on-container-exit --exit-code-from harness-runner
```
> **Note**: Host virtual environments (`.venv`) and `node_modules` are automatically isolated via anonymous container volumes to prevent cross-architecture collisions. Generated outputs in `examples/` are directly mounted and written to your host filesystem.

### 4. Run An Individual Tool Harness
Want to iterate on a single tool? Start the mocks and run its specific harness:
```bash
# 1. Start mock target containers
docker compose -f docker/docker-compose.yml up -d

# 2. Run your tool of choice:
bash harnesses/promptfoo/run.sh   # Run Promptfoo (OWASP LLM01, LLM02, LLM06, ASI02, ASI05)
bash harnesses/pyrit/run.sh       # Run PyRIT (Crescendo, Converters, RAG Poisoning)
bash harnesses/garak/run.sh       # Run Garak (Dan, PromptInject, Encoding, XSS)
bash harnesses/rampart/run.sh     # Run RAMPART (Agentic red-teaming, RCE, Confused Deputy)
bash harnesses/inspect_ai/run.sh  # Run Inspect AI (UK AISI .eval bundle generation)
bash harnesses/deepteam/run.sh    # Run DeepTeam (OWASP/ATLAS attack progression trees)

# 3. Validate generated fixtures
python3 scripts/validate_fixtures.py

# 4. Tear down mocks
docker compose -f docker/docker-compose.yml down
```

---

## 🐍 Unified Downstream Parser SDK (`sdk/adversarial_toolio`)

We include a standardized Python client library to normalize heterogeneous findings across all 6 frameworks into a unified data model:

```python
from adversarial_toolio import load_all_fixtures, ToolType, ThreatCategory

# Ingest all frozen fixtures across all 6 tools into unified Finding models
report = load_all_fixtures()

print(f"Loaded {len(report.findings)} findings across all frameworks.")

# Query specific threat categories (e.g., Prompt Injection or Data Leakage)
for finding in report.findings:
    if not finding.passed:
        print(f"[{finding.tool.value.upper()}] 🚨 {finding.category.value} ({finding.threat_id}): {finding.name}")
        print(f"   Severity: {finding.severity} | Attack Output: {finding.output[:80]}...")
```

### Direct Fixture Parsing Examples

#### Loading Garak Hits
```python
import json

with open("examples/garak/outputs/garak_scan.hitlog.jsonl", "r") as f:
    for line in f:
        hit = json.loads(line)
        print(f"[{hit.get('goal', 'VULN')}] Probe: {hit.get('probe')} | Trigger: {hit.get('trigger')}")
```

#### TypeScript / Node.js: Parsing Promptfoo Results
```typescript
import results from "./examples/promptfoo/outputs/promptfoo_results.json";

const failedTests = results.results.filter((r: any) => !r.success);
console.log(`Found ${failedTests.length} adversarial vulnerabilities detected!`);
```

---

## 🤝 How to Contribute

We follow a standard GitHub Fork & Pull Request workflow:

1. **Fork the Repo:** Click the **Fork** button at the top right of this page.
2. **Clone & Branch:**
   ```bash
   git clone https://github.com/<your-username>/adversarial_testing_tool_io_examples.git
   cd adversarial_testing_tool_io_examples
   git checkout -b feat/add-inspect-ai-harness
   ```
3. **Make Your Changes:** Add your tool adapter, new attack inputs, or converters.
4. **Validate Fixtures:**
   ```bash
   python3 scripts/validate_fixtures.py
   ```
5. **Commit with Conventional Commits:**
   ```bash
   git commit -m "feat(harness): add Inspect AI evaluation harness and mock target"
   ```
6. **Open a Pull Request:** Push to your fork and submit a PR to `master`. We review quickly!

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for full details, coding standards, and community guidelines.

---

## 📄 License & Community

- **License:** Distributed under the [MIT License](LICENSE).
- **Contributing:** Please see [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **Security & Ethics:** All probes, configurations, and mock payloads in this repository are strictly designed for **defensive security auditing, software QA, and safety evaluation benchmarking**.

---

<div align="center">
  <sub>Maintained with ❤️ for the open-source AI Safety & Security community. Star ⭐ this repository if you find it useful!</sub>
</div>
