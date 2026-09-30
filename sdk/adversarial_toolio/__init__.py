"""Adversarial Tool I/O Parser SDK.

Unified loader and parsing library for downstream developers to ingest
adversarial testing artifacts across Promptfoo, PyRIT, Garak, RAMPART,
Inspect AI, and DeepTeam without needing the testing tools themselves.
"""

from pathlib import Path

from .models import Finding, ThreatCategory, UnifiedReport
from .parsers import (
    parse_deepteam,
    parse_garak,
    parse_inspect_ai,
    parse_promptfoo,
    parse_pyrit,
    parse_rampart,
)

__version__ = "1.0.0"

def load_all_fixtures(examples_root: Path | None = None) -> UnifiedReport:
    """Load and normalize all tool I/O fixtures into a single UnifiedReport."""
    if examples_root is None:
        examples_root = Path(__file__).resolve().parents[2] / "examples"

    all_findings: list[Finding] = []
    tools_found = []

    # 1. Promptfoo
    pf_json = examples_root / "promptfoo" / "outputs" / "promptfoo_results.json"
    if pf_json.exists():
        all_findings.extend(parse_promptfoo(pf_json))
        tools_found.append("promptfoo")

    # 2. PyRIT
    pyrit_json = examples_root / "pyrit" / "outputs" / "pyrit_eval_results.json"
    if pyrit_json.exists():
        all_findings.extend(parse_pyrit(pyrit_json))
        tools_found.append("pyrit")

    # 3. Garak
    garak_jsonl = examples_root / "garak" / "outputs" / "garak_scan.report.jsonl"
    if garak_jsonl.exists():
        all_findings.extend(parse_garak(garak_jsonl))
        tools_found.append("garak")

    # 4. RAMPART
    rampart_json = examples_root / "rampart" / "outputs" / "rampart_eval.json"
    if rampart_json.exists():
        all_findings.extend(parse_rampart(rampart_json))
        tools_found.append("rampart")

    # 5. Inspect AI
    inspect_json = examples_root / "inspect_ai" / "outputs" / "agent_safety_task.eval.json"
    if inspect_json.exists():
        all_findings.extend(parse_inspect_ai(inspect_json))
        tools_found.append("inspect_ai")

    # 6. DeepTeam
    deepteam_json = examples_root / "deepteam" / "outputs" / "deepteam_vulnerability_matrix.json"
    if deepteam_json.exists():
        all_findings.extend(parse_deepteam(deepteam_json))
        tools_found.append("deepteam")

    passed_count = sum(1 for f in all_findings if f.passed)
    vuln_count = len(all_findings) - passed_count

    return UnifiedReport(
        total_findings=len(all_findings),
        passed_count=passed_count,
        vulnerability_count=vuln_count,
        tools_covered=sorted(set(tools_found)),
        findings=all_findings
    )
