"""Unified Data Models for Adversarial Tool I/O Findings."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class ThreatCategory(str, Enum):
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
    output_text: Optional[str] = None
    rationale: Optional[str] = None
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)

class UnifiedReport(BaseModel):
    total_findings: int
    passed_count: int
    vulnerability_count: int
    tools_covered: List[str]
    findings: List[Finding]

    def filter_by_tool(self, tool_name: str) -> List[Finding]:
        return [f for f in self.findings if f.tool.lower() == tool_name.lower()]

    def filter_by_category(self, category: ThreatCategory) -> List[Finding]:
        return [f for f in self.findings if f.threat_category == category]
