#!/usr/bin/env python3
"""Convert Promptfoo JSON evaluation results to standard SARIF 2.1.0.

Provides standard OASIS SARIF output for downstream SIEM, GitHub Security Code Scanning,
and vulnerability dashboard ingestion.
"""

import json
import os
import sys
from typing import Any, Dict, List

def convert_promptfoo_to_sarif(results_path: str, sarif_path: str):
    with open(results_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Promptfoo results can be under "results" or top-level
    raw_results = data.get("results", {})
    test_runs = raw_results.get("results", []) if isinstance(raw_results, dict) else []

    rules: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for idx, test in enumerate(test_runs):
        grading = test.get("gradingResult", {})
        passed = grading.get("pass", True)
        test_case = test.get("testCase", {})
        description = test_case.get("description", f"Test Case {idx + 1}")
        prompt_info = test.get("prompt", {})
        raw_prompt = prompt_info.get("raw", "") if isinstance(prompt_info, dict) else str(prompt_info)
        response_info = test.get("response", {})
        output_text = response_info.get("output", "") if isinstance(response_info, dict) else str(response_info)
        reason = grading.get("reason", test.get("error", "Security assertion failed"))

        # Determine Rule ID based on description
        rule_id = "LLM-GENERIC-VULNERABILITY"
        rule_name = "LLM Security Assertion Failure"
        rule_desc = description

        if "LLM01" in description or "Direct Prompt Injection" in description:
            rule_id = "OWASP-LLM01-PROMPT-INJECTION"
            rule_name = "Direct Prompt Injection / Jailbreak"
        elif "LLM06" in description or "Data Leakage" in description:
            rule_id = "OWASP-LLM06-SENSITIVE-DATA-LEAKAGE"
            rule_name = "Sensitive Information Disclosure / PII Leakage"
        elif "LLM02" in description or "Insecure Output" in description:
            rule_id = "OWASP-LLM02-INSECURE-OUTPUT-HANDLING"
            rule_name = "Insecure Output Handling / XSS"
        elif "Auth Bypass" in description or "Elevation" in description:
            rule_id = "AUTH-01-PRIVILEGE-ESCALATION"
            rule_name = "Authorization & Privilege Escalation Bypass"
        elif "Indirect Prompt Injection" in description:
            rule_id = "OWASP-LLM01-INDIRECT-PROMPT-INJECTION"
            rule_name = "Indirect Prompt Injection via Untrusted Payload"

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "fullDescription": {"text": rule_desc},
                "help": {
                    "text": f"Evaluate mitigations against {rule_name}. Verify that model outputs do not echo unvalidated instructions, secrets, or unauthorized state modifications."
                },
                "properties": {
                    "category": "security",
                    "tags": ["ai-safety", "owasp-llm-top-10", "adversarial-testing"]
                }
            }

        if not passed:
            sarif_results.append({
                "ruleId": rule_id,
                "level": "error",
                "message": {
                    "text": f"{description}: {reason}\nTarget Response: {output_text[:200]}..."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "harnesses/promptfoo/promptfooconfig.yaml"
                            },
                            "region": {
                                "startLine": 1 + idx * 5,
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "prompt": raw_prompt,
                    "response": output_text,
                    "testDescription": description
                }
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Promptfoo Adversarial Evaluator",
                        "version": "0.123.1",
                        "informationUri": "https://promptfoo.dev",
                        "rules": list(rules.values())
                    }
                },
                "results": sarif_results
            }
        ]
    }

    os.makedirs(os.path.dirname(os.path.abspath(sarif_path)), exist_ok=True)
    with open(sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    print(f"Generated SARIF report: {sarif_path} ({len(sarif_results)} findings)")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python promptfoo_to_sarif.py <results.json> <output.sarif>")
        sys.exit(1)
    convert_promptfoo_to_sarif(sys.argv[1], sys.argv[2])
