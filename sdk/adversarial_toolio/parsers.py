"""Parsers converting tool-specific outputs into unified Findings."""

import json
import sqlite3
from pathlib import Path
from typing import List
from .models import Finding, ThreatCategory

def map_category(text: str) -> ThreatCategory:
    tl = text.lower()
    if "rag" in tl or "memory" in tl:
        return ThreatCategory.RAG_POISONING
    if "sandbox" in tl or "escape" in tl:
        return ThreatCategory.SANDBOX_ESCAPE
    if "confused" in tl or "deputy" in tl or "egress" in tl or "webhook" in tl:
        return ThreatCategory.CONFUSED_DEPUTY
    if "wallet" in tl or "denial" in tl or "resource" in tl:
        return ThreatCategory.DENIAL_OF_WALLET
    if "dan" in tl or "jailbreak" in tl or "prompt_injection" in tl or "llm01" in tl:
        return ThreatCategory.PROMPT_INJECTION
    if "data_leakage" in tl or "leak" in tl or "credential" in tl or "llm06" in tl:
        return ThreatCategory.DATA_LEAKAGE
    if "auth" in tl or "privilege" in tl or "root" in tl or "admin" in tl:
        return ThreatCategory.AUTH_BYPASS
    if "indirect" in tl or "xpia" in tl:
        return ThreatCategory.INDIRECT_INJECTION
    if "xss" in tl or "script" in tl or "llm02" in tl:
        return ThreatCategory.XSS_OUTPUT_HANDLING
    if "cwe" in tl or "code" in tl:
        return ThreatCategory.INSECURE_CODE
    if "benign" in tl or "control" in tl:
        return ThreatCategory.BENIGN_CONTROL
    return ThreatCategory.OTHER

def parse_promptfoo(json_path: Path) -> List[Finding]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    results = data.get("results", {}).get("results", [])
    for idx, r in enumerate(results):
        prompt = r.get("prompt", {}).get("raw", "")
        response = r.get("response", {}).get("output", "")
        desc = r.get("description", f"promptfoo-test-{idx+1}")
        success = r.get("success", False)
        score = r.get("score", 1.0 if success else 0.0)

        findings.append(Finding(
            id=f"promptfoo-{idx+1}",
            tool="promptfoo",
            threat_category=map_category(desc),
            passed=success,
            score=score,
            input_prompt=prompt,
            output_text=response,
            rationale=r.get("error") or ("Passed all assertions" if success else "Assertion failure"),
            raw_metadata={"grading_result": r.get("gradingResult", {})}
        ))
    return findings

def parse_pyrit(json_path: Path) -> List[Finding]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for idx, r in enumerate(data.get("results", [])):
        score_val = r.get("score", 0.0)
        passed = (score_val == 0.0)  # PyRIT score 1.0 = vulnerability detected
        findings.append(Finding(
            id=f"pyrit-{idx+1}",
            tool="pyrit",
            threat_category=map_category(r.get("category", "")),
            passed=passed,
            score=0.0 if not passed else 1.0,
            input_prompt=r.get("input_prompt", ""),
            output_text=r.get("output_response", ""),
            rationale=r.get("rationale", ""),
            raw_metadata={"session_id": r.get("session_id"), "converter": r.get("converter")}
        ))
    return findings

def parse_garak(jsonl_path: Path) -> List[Finding]:
    findings = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if not line.strip():
                continue
            entry = json.loads(line)
            # Focus on test evaluations
            if entry.get("entry_type") == "eval":
                probe = entry.get("probe", "")
                detector = entry.get("detector", "")
                passed = (entry.get("passed", 0) > 0)
                findings.append(Finding(
                    id=f"garak-{idx+1}",
                    tool="garak",
                    threat_category=map_category(probe),
                    passed=passed,
                    score=1.0 if passed else 0.0,
                    input_prompt=f"Probe: {probe}",
                    output_text=f"Detector: {detector}",
                    rationale=f"Detector {detector} scored probe {probe}",
                    raw_metadata=entry
                ))
    return findings

def parse_rampart(json_path: Path) -> List[Finding]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    runs = data.get("runs", [])
    for idx, run in enumerate(runs):
        safe = run.get("safe", False)
        name = run.get("name", f"rampart-test-{idx+1}")
        category = run.get("harm_category", "")
        summary = run.get("summary", "")

        findings.append(Finding(
            id=f"rampart-{idx+1}",
            tool="rampart",
            threat_category=map_category(category or name),
            passed=safe,
            score=1.0 if safe else 0.0,
            input_prompt=name,
            output_text=summary,
            rationale=summary,
            raw_metadata=run
        ))
    return findings

def parse_inspect_ai(json_path: Path) -> List[Finding]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    samples = data.get("samples", [])
    for idx, s in enumerate(samples):
        prompt = s.get("input", "")
        output_choice = s.get("output", {}).get("choices", [{}])[0].get("message", {}).get("content", "")
        meta = s.get("metadata", {})
        scores = s.get("scores", {})

        score_val = 1.0
        rationale = ""
        for sc_name, sc_data in scores.items():
            score_val = sc_data.get("value", 1.0)
            rationale = sc_data.get("explanation", "")
            break

        passed = (score_val == 1.0)
        findings.append(Finding(
            id=f"inspect-{idx+1}",
            tool="inspect_ai",
            threat_category=map_category(meta.get("category", "")),
            passed=passed,
            score=score_val,
            input_prompt=prompt,
            output_text=output_choice,
            rationale=rationale,
            raw_metadata=meta
        ))
    return findings

def parse_deepteam(json_path: Path) -> List[Finding]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    matrix = data.get("matrix", [])
    for idx, m in enumerate(matrix):
        status = m.get("status", "")
        passed = (status == "PROTECTED")
        findings.append(Finding(
            id=f"deepteam-{idx+1}",
            tool="deepteam",
            threat_category=map_category(m.get("category", "") + " " + m.get("name", "")),
            passed=passed,
            score=1.0 if passed else 0.0,
            input_prompt=m.get("name", ""),
            output_text="\n".join(m.get("findings", [])),
            rationale=f"Status: {status}, Severity: {m.get('severity', '')}",
            raw_metadata=m
        ))
    return findings
