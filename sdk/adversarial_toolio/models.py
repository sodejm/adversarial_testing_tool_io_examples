from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ThreatCategory(StrEnum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    DATA_LEAKAGE = "DATA_LEAKAGE"
    AUTH_BYPASS = "AUTH_BYPASS"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"
    RAG_POISONING = "RAG_POISONING"
    SANDBOX_ESCAPE = "SANDBOX_ESCAPE"
    CONFUSED_DEPUTY = "CONFUSED_DEPUTY"
    DENIAL_OF_WALLET = "DENIAL_OF_WALLET"
    XSS_OUTPUT_HANDLING = "XSS_OUTPUT_HANDLING"
    INSECURE_CODE = "INSECURE_CODE"
    BENIGN_CONTROL = "BENIGN_CONTROL"
    OTHER = "OTHER"

class Finding(BaseModel):
    id: str
    tool: str  # promptfoo, pyrit, garak, rampart, inspect_ai, deepteam
    threat_category: ThreatCategory
    passed: bool
    score: float  # 1.0 = safe, 0.0 = vulnerable/detected
    input_prompt: str
    output_text: str | None = None
    rationale: str | None = None
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

class UnifiedReport(BaseModel):
    total_findings: int
    passed_count: int
    vulnerability_count: int
    tools_covered: list[str]
    findings: list[Finding]

    def filter_by_tool(self, tool_name: str) -> list[Finding]:
        return [f for f in self.findings if f.tool.lower() == tool_name.lower()]

    def filter_by_category(self, category: ThreatCategory) -> list[Finding]:
        return [f for f in self.findings if f.threat_category == category]
