"""RAMPART pytest configuration and reporting sink registration.

Registers session-scoped ReportSinks to serialize structured RAMPART evaluation reports
containing full conversation transcripts, tool calls, side effects, and harm category breakdowns.
"""

import json
import os
from pathlib import Path
from typing import Any
import pytest
from rampart.reporting.sink import ReportSink
from rampart.reporting.json_file import JsonFileReportSink
from rampart.pytest_plugin._session import TestRunReport

class RAMPARTEvalFileSink:
    """Report sink that outputs the evaluation report to a deterministic JSON path."""

    def __init__(self, target_path: Path):
        self.target_path = target_path
        self._sink_helper = JsonFileReportSink(output_dir=target_path.parent)

    async def emit_async(self, *, report: TestRunReport) -> None:
        self.target_path.parent.mkdir(parents=True, exist_ok=True)
        data = self._sink_helper._serialize_report(report)
        self.target_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        print(f"\n[RAMPART] Emitted evaluation report to: {self.target_path}")

@pytest.fixture(scope="session")
def rampart_sinks():
    output_dir = Path(os.environ.get("RAMPART_OUTPUT_DIR", str(Path(__file__).resolve().parents[2] / "examples" / "rampart" / "outputs")))
    output_file = output_dir / "rampart_eval.json"
    return [RAMPARTEvalFileSink(output_file)]
