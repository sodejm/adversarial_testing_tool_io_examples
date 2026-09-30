#!/usr/bin/env python3
"""Garak Adversarial Runner.

Executes Garak LLM vulnerability probes against local mock targets:
- promptinject: HijackHateHumans (OWASP LLM01)
- dan: Ablation_Dan_11_0 (OWASP LLM01)
- encoding: InjectBase64 (OWASP LLM01)
- xss: MarkdownXSS (OWASP LLM02)
- leaktoppo / leakreplay: GuardianCloze (OWASP LLM06)

Captures and stores authentic Tool I/O artifacts:
- garak_probes.yaml (Input configuration)
- garak_scan.report.jsonl (Raw scan report)
- garak_report.html (Interactive HTML report)
- garak_scan.hitlog.jsonl (Detailed vulnerability hitlog)
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
import yaml

def parse_args():
    parser = argparse.ArgumentParser(description="Run Garak adversarial evaluation against mock LLM API")
    parser.add_argument(
        "--config",
        default=os.environ.get("GARAK_CONFIG", str(Path(__file__).parent / "garak_probes.yaml")),
        help="Path to garak_probes.yaml config file"
    )
    parser.add_argument(
        "--target-url",
        default=os.environ.get("GARAK_TARGET_URL", "http://localhost:8000/v1"),
        help="Target OpenAI-compatible endpoint"
    )
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("GARAK_OUTPUT_DIR", str(Path(__file__).resolve().parents[2] / "examples" / "garak" / "outputs")),
        help="Directory to save output artifacts"
    )
    parser.add_argument(
        "--input-dir",
        default=os.environ.get("GARAK_INPUT_DIR", str(Path(__file__).resolve().parents[2] / "examples" / "garak" / "inputs")),
        help="Directory to save input artifacts"
    )
    return parser.parse_args()

def main():
    args = parse_args()
    config_path = Path(args.config)
    output_dir = Path(args.output_dir)
    input_dir = Path(args.input_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    input_dir.mkdir(parents=True, exist_ok=True)

    print(f"=== Running Garak Adversarial Probing Runner ===")
    print(f"Target URL: {args.target_url}")
    print(f"Output Directory: {output_dir}")

    # Copy config to input directory
    target_config_copy = input_dir / "garak_probes.yaml"
    shutil.copyfile(config_path, target_config_copy)
    print(f"Copied probe configuration to: {target_config_copy}")

    # Load probe specifications
    with open(config_path, "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f)

    probes = [p["id"] for p in config_data.get("probes", [])]
    probes_str = ",".join(probes)
    target_conf = config_data.get("target", {})
    model_type = target_conf.get("model_type", "openai.OpenAICompatible")
    model_name = target_conf.get("model_name", "gpt-3.5-turbo")
    report_prefix = config_data.get("runtime", {}).get("report_prefix", "garak_scan")

    # Setup environment
    env = os.environ.copy()
    env["OPENAICOMPATIBLE_API_KEY"] = target_conf.get("api_key", "mock-garak-offline-key")

    # Generate runtime garak config with target URI to ensure correct endpoint routing
    runtime_garak_config = Path("/tmp") / f"garak_runtime_{os.getpid()}.yaml"
    garak_sys_config = {
        "plugins": {
            "generators": {
                "openai": {
                    "OpenAICompatible": {
                        "uri": args.target_url
                    }
                }
            }
        }
    }
    with open(runtime_garak_config, "w", encoding="utf-8") as f:
        yaml.dump(garak_sys_config, f)

    cmd = [
        sys.executable, "-m", "garak",
        "--config", str(runtime_garak_config),
        "--target_type", model_type,
        "--target_name", model_name,
        "--probes", probes_str,
        "--generations", str(config_data.get("runtime", {}).get("generations", 1)),
        "--parallel_attempts", str(config_data.get("runtime", {}).get("parallel_attempts", 16)),
        "--report_prefix", report_prefix,
        "--skip_unknown"
    ]

    print(f"Executing: {' '.join(cmd)}")
    start_time = time.time()
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    elapsed = time.time() - start_time
    if runtime_garak_config.exists():
        runtime_garak_config.unlink()
    print(f"Garak scan completed in {elapsed:.2f}s (returncode: {proc.returncode})")

    if proc.stdout:
        print("\n--- Garak Standard Output ---")
        print(proc.stdout[-1500:] if len(proc.stdout) > 1500 else proc.stdout)

    if proc.stderr:
        print("\n--- Garak Standard Error ---")
        print(proc.stderr[-1000:] if len(proc.stderr) > 1000 else proc.stderr)

    # Locate generated reports
    possible_dirs = [
        Path.cwd(),
        Path.home() / ".local" / "share" / "garak" / "garak_runs",
        Path.home() / ".garak" / "garak_runs",
        Path("/tmp/garak")
    ]

    found_reports = []
    found_hitlogs = []
    found_htmls = []

    for search_dir in possible_dirs:
        if search_dir.exists():
            found_reports.extend(search_dir.glob(f"{report_prefix}*.report.jsonl"))
            found_hitlogs.extend(search_dir.glob(f"{report_prefix}*.hitlog.jsonl"))
            found_htmls.extend(search_dir.glob(f"{report_prefix}*.report.html"))

    # Sort by modification time descending to get the freshest run
    found_reports = sorted(found_reports, key=lambda p: p.stat().st_mtime, reverse=True)
    found_hitlogs = sorted(found_hitlogs, key=lambda p: p.stat().st_mtime, reverse=True)
    found_htmls = sorted(found_htmls, key=lambda p: p.stat().st_mtime, reverse=True)

    dest_report = output_dir / f"{report_prefix}.report.jsonl"
    dest_html = output_dir / "garak_report.html"
    dest_hitlog = output_dir / f"{report_prefix}.hitlog.jsonl"

    if found_reports:
        shutil.copyfile(found_reports[0], dest_report)
        print(f"Saved report: {dest_report} ({dest_report.stat().st_size} bytes)")
    else:
        print("WARNING: No .report.jsonl file found!", file=sys.stderr)

    if found_hitlogs:
        shutil.copyfile(found_hitlogs[0], dest_hitlog)
        print(f"Saved hitlog: {dest_hitlog} ({dest_hitlog.stat().st_size} bytes)")

    if found_htmls and found_htmls[0].stat().st_size > 0:
        shutil.copyfile(found_htmls[0], dest_html)
        print(f"Saved HTML report: {dest_html} ({dest_html.stat().st_size} bytes)")
    elif dest_report.exists():
        # Generate HTML report programmatically via Garak digest if not generated
        try:
            import garak.analyze.report_digest as rd
            print("Generating HTML report from report digest...")
            digest = rd.build_digest(str(dest_report))
            html_content = rd.build_html(digest)
            with open(dest_html, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"Generated HTML report: {dest_html} ({dest_html.stat().st_size} bytes)")
        except Exception as e:
            print(f"Notice: Garak HTML digest builder returned: {e}")

    print("Garak runner execution complete.")

if __name__ == "__main__":
    main()
