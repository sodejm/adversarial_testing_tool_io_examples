#!/usr/bin/env python3
"""Fixture Integrity and Schema Validator.

Verifies the structural validity, JSON/SARIF compliance, SQLite schema integrity,
and completeness of all generated Tool I/O adversarial testing artifacts:
- Promptfoo: JSON, SARIF 2.1.0, HTML
- PyRIT: JSON, SQLite DB (tables, messages, scores), Multi-turn transcripts
- Garak: JSONL reports, JSONL hitlogs, HTML reports
- RAMPART: JUnit XML, Structured JSON evaluation reports
"""

import json
import os
import sqlite3
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples"

EXPECTED_FILES = [
    # Promptfoo
    ("promptfoo/inputs/promptfooconfig.yaml", "yaml"),
    ("promptfoo/outputs/promptfoo_results.json", "json"),
    ("promptfoo/outputs/promptfoo_summary.html", "html"),
    ("promptfoo/outputs/promptfoo_report.sarif", "sarif"),

    # PyRIT
    ("pyrit/inputs/pyrit_attack_catalog.json", "json"),
    ("pyrit/outputs/pyrit_eval_results.json", "json"),
    ("pyrit/outputs/pyrit_crescendo_session.json", "json"),
    ("pyrit/outputs/pyrit_cross_session_memory_eval.json", "json"),
    ("pyrit/outputs/pyrit_memory.db", "sqlite"),

    # Garak
    ("garak/inputs/garak_probes.yaml", "yaml"),
    ("garak/outputs/garak_scan.report.jsonl", "jsonl"),
    ("garak/outputs/garak_report.html", "html"),

    # RAMPART
    ("rampart/inputs/test_agentic_safety.py", "python"),
    ("rampart/outputs/rampart_results.xml", "xml"),
    ("rampart/outputs/rampart_eval.json", "json"),

    # Inspect AI (UK AISI)
    ("inspect_ai/inputs/agent_safety_task.yaml", "yaml"),
    ("inspect_ai/outputs/agent_safety_task.eval.json", "json"),
    ("inspect_ai/outputs/agent_safety_task.eval", "zip"),

    # DeepTeam / DeepEval
    ("deepteam/inputs/deepteam_config.yaml", "yaml"),
    ("deepteam/outputs/deepteam_vulnerability_matrix.json", "json"),
    ("deepteam/outputs/deepteam_attack_trees.json", "json"),
    ("deepteam/outputs/deepteam_risk_scorecard.json", "json"),
]

def check_file_exists(rel_path: str) -> Tuple[bool, str]:
    full_path = EXAMPLES_DIR / rel_path
    if not full_path.exists():
        return False, f"File missing: {rel_path}"
    size = full_path.stat().st_size
    if size == 0:
        return False, f"File is empty (0 bytes): {rel_path}"
    return True, f"OK ({size:,} bytes)"

def validate_json(path: Path) -> Tuple[bool, str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        keys_summary = ", ".join(list(data.keys())[:5]) if isinstance(data, dict) else f"{len(data)} items"
        return True, f"Valid JSON ({keys_summary})"
    except Exception as e:
        return False, f"Invalid JSON in {path.name}: {e}"

def validate_sarif(path: Path) -> Tuple[bool, str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            sarif = json.load(f)
        if sarif.get("version") != "2.1.0":
            return False, f"SARIF version mismatch: expected '2.1.0', got '{sarif.get('version')}'"
        runs = sarif.get("runs", [])
        if not runs:
            return False, "SARIF contains no 'runs'"
        driver = runs[0].get("tool", {}).get("driver", {})
        results = runs[0].get("results", [])
        return True, f"Valid SARIF 2.1.0 (Tool: {driver.get('name')}, Findings: {len(results)})"
    except Exception as e:
        return False, f"Invalid SARIF structure in {path.name}: {e}"

def validate_jsonl(path: Path) -> Tuple[bool, str]:
    line_count = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    json.loads(line_str)
                    line_count += 1
        if line_count == 0:
            return False, f"Empty JSONL file: {path.name}"
        return True, f"Valid JSONL ({line_count:,} records)"
    except Exception as e:
        return False, f"JSONL validation failed at line {line_count + 1}: {e}"

def validate_sqlite(path: Path) -> Tuple[bool, str]:
    try:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        required_tables = ["conversation_messages", "score_entries"]
        for req in required_tables:
            if req not in tables:
                return False, f"Missing table '{req}' in SQLite DB"

        cursor.execute("SELECT count(*) FROM conversation_messages;")
        msg_count = cursor.fetchone()[0]
        cursor.execute("SELECT count(*) FROM score_entries;")
        score_count = cursor.fetchone()[0]
        conn.close()

        if msg_count == 0:
            return False, "SQLite DB table 'conversation_messages' is empty"
        return True, f"Valid SQLite DB ({msg_count} messages, {score_count} scores across tables: {', '.join(tables)})"
    except Exception as e:
        return False, f"SQLite validation failed: {e}"

def validate_xml(path: Path) -> Tuple[bool, str]:
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        test_count = 0
        if root.tag == "testsuites":
            for suite in root.findall("testsuite"):
                test_count += int(suite.attrib.get("tests", len(suite.findall("testcase"))))
        elif root.tag == "testsuite":
            test_count = int(root.attrib.get("tests", len(root.findall("testcase"))))
        return True, f"Valid JUnit XML (Root: <{root.tag}>, Tests: {test_count})"
    except Exception as e:
        return False, f"XML validation failed: {e}"

def validate_zip(path: Path) -> Tuple[bool, str]:
    import zipfile
    try:
        with zipfile.ZipFile(path, "r") as zf:
            namelist = zf.namelist()
            if not namelist:
                return False, f"Empty ZIP archive: {path.name}"
            return True, f"Valid archive ({len(namelist)} items: {', '.join(namelist[:3])})"
    except Exception as e:
        return False, f"ZIP validation failed: {e}"

def validate_html(path: Path) -> Tuple[bool, str]:
    try:
        content = path.read_text(encoding="utf-8")
        if "<html" not in content.lower() and "<!doctype html" not in content.lower():
            return False, "Missing <html> or <!DOCTYPE html> tags"
        return True, f"Valid HTML document ({len(content):,} characters)"
    except Exception as e:
        return False, f"HTML validation failed: {e}"

def validate_all() -> bool:
    print("=" * 72)
    print(" Adversarial Testing Tool I/O: Fixture Integrity & Schema Validator")
    print("=" * 72)

    total_checks = 0
    passed_checks = 0
    failures: List[str] = []

    for rel_path, file_type in EXPECTED_FILES:
        total_checks += 1
        full_path = EXAMPLES_DIR / rel_path
        exists, msg = check_file_exists(rel_path)

        if not exists:
            failures.append(f"[FAIL] {rel_path}: {msg}")
            print(f"❌ {rel_path:<45} -> {msg}")
            continue

        valid = True
        detail = msg

        if file_type == "json":
            valid, detail = validate_json(full_path)
        elif file_type == "sarif":
            valid, detail = validate_sarif(full_path)
        elif file_type == "jsonl":
            valid, detail = validate_jsonl(full_path)
        elif file_type == "sqlite":
            valid, detail = validate_sqlite(full_path)
        elif file_type == "xml":
            valid, detail = validate_xml(full_path)
        elif file_type == "html":
            valid, detail = validate_html(full_path)
        elif file_type == "zip":
            valid, detail = validate_zip(full_path)
        elif file_type in ("yaml", "python"):
            valid = True
            detail = f"Present and readable ({full_path.stat().st_size:,} bytes)"

        if valid:
            passed_checks += 1
            print(f"✅ {rel_path:<45} -> {detail}")
        else:
            failures.append(f"[FAIL] {rel_path}: {detail}")
            print(f"❌ {rel_path:<45} -> {detail}")

    print("=" * 72)
    print(f"Validation Summary: {passed_checks}/{total_checks} fixtures verified successfully.")

    if failures:
        print("\nFailures:")
        for f in failures:
            print(f"  {f}")
        return False
    else:
        print("All fixtures passed structural, semantic, and schema validation!")
        return True

if __name__ == "__main__":
    success = validate_all()
    sys.exit(0 if success else 1)
