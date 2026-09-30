"""Tests for the Adversarial Tool I/O Unified Parser SDK."""

import sys
from pathlib import Path
import pytest

# Add sdk to path
SDK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SDK_ROOT))

from adversarial_toolio import load_all_fixtures, ThreatCategory

def test_load_all_fixtures():
    examples_dir = Path(__file__).resolve().parents[2] / "examples"
    report = load_all_fixtures(examples_dir)

    assert report.total_findings > 0, "Expected findings to be parsed"
    assert len(report.tools_covered) >= 4, f"Expected at least 4 tools covered, got {report.tools_covered}"

    # Verify tool filtering
    pf_findings = report.filter_by_tool("promptfoo")
    assert len(pf_findings) > 0, "Expected Promptfoo findings"

    pyrit_findings = report.filter_by_tool("pyrit")
    assert len(pyrit_findings) > 0, "Expected PyRIT findings"

    # Verify category filtering
    injection_findings = report.filter_by_category(ThreatCategory.PROMPT_INJECTION)
    assert len(injection_findings) > 0, "Expected Prompt Injection findings"

    print(f"\nSDK Test Passed: {report.total_findings} findings loaded across {report.tools_covered}")

if __name__ == "__main__":
    test_load_all_fixtures()
