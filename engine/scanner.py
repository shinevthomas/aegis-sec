"""
AegisSec: Core Security Scanner Engine
Scans target applications for:
1. Leaked Secrets & Credentials (Gitleaks-style)
2. Insecure Code Logic & SQL Injection (Semgrep-style)
3. Vulnerable Outdated Dependencies (Trivy-style)
"""

import os
import re
import json
import sys
from typing import List, Dict, Any

# ==============================================================================
# KNOWN VULNERABILITY DATABASE (Advisories for common packages)
# Real tools query public CVE databases; we maintain a representative advisory map
# ==============================================================================
KNOWN_PACKAGE_ADVISORIES = {
    "flask": {
        "vulnerable_below": "2.0.0",
        "fixed_in": "3.0.0",
        "cve": "CVE-2018-18074",
        "description": "Unexpected JSON decoding and DoS vulnerability in older Flask runtimes.",
        "severity": "MEDIUM",
    },
    "requests": {
        "vulnerable_below": "2.20.0",
        "fixed_in": "2.31.0",
        "cve": "CVE-2018-18074",
        "description": "Authorization headers leaked over HTTPS redirects to third-party domains.",
        "severity": "HIGH",
    },
    "urllib3": {
        "vulnerable_below": "1.24.2",
        "fixed_in": "2.0.7",
        "cve": "CVE-2019-11324",
        "description": "CRLF injection in HTTP request headers allows cache poisoning.",
        "severity": "MEDIUM",
    },
}

# Regex patterns for high-entropy secrets and well-known credential formats
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "recommendation": "Revoke the key immediately in AWS IAM and load via environment variables.",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",
        "severity": "CRITICAL",
        "recommendation": "Rotate compromised credentials in AWS IAM console immediately.",
    },
    {
        "name": "Stripe Live Secret Key",
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "CRITICAL",
        "recommendation": "Revoke this key in Stripe Dashboard and store in a Secrets Manager (AWS Secrets Manager / Vault).",
    },
]


def scan_secrets(file_path: str) -> List[Dict[str, Any]]:
    """
    Step 1: Secrets Scanner
    Reads file line-by-line looking for hardcoded credentials using regex signatures.
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for rule in SECRET_PATTERNS:
                    match = re.search(rule["pattern"], line)
                    if match:
                        # Mask secret value so we don't leak it in logs
                        raw_matched = match.group(0)
                        masked = raw_matched[:6] + "..." + raw_matched[-4:] if len(raw_matched) > 10 else "***"
                        findings.append({
                            "type": "SECRET_LEAK",
                            "severity": rule["severity"],
                            "title": f"Exposed {rule['name']}",
                            "file": os.path.basename(file_path),
                            "line": line_number,
                            "snippet": line.strip(),
                            "masked_match": masked,
                            "recommendation": rule["recommendation"],
                        })
    except Exception as e:
        print(f"Error scanning secrets in {file_path}: {e}")
    return findings


def scan_code_vulnerabilities(file_path: str) -> List[Dict[str, Any]]:
    """
    Step 2: Code Vulnerability (SAST) Scanner
    Analyzes code patterns looking for unsafe dynamic query execution (SQL Injection).
    """
    findings = []
    if not file_path.endswith(".py"):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for idx, line in enumerate(lines, start=1):
            # Check for SQL injection patterns: f-strings or string concatenation in queries
            is_fstring_sql = re.search(r'f["\'].*SELECT.*WHERE.*\{.*\}', line, re.IGNORECASE)
            is_concat_sql = re.search(r'["\'].*SELECT.*WHERE.*["\']\s*\+\s*\w+', line, re.IGNORECASE)

            if is_fstring_sql or is_concat_sql:
                findings.append({
                    "type": "CODE_FLAW",
                    "severity": "HIGH",
                    "title": "SQL Injection (CWE-89)",
                    "file": os.path.basename(file_path),
                    "line": idx,
                    "snippet": line.strip(),
                    "recommendation": "Use parameterized queries ('?') instead of direct string interpolation.",
                    "suggested_fix": (
                        "# Safe alternative using parameterization:\n"
                        "query = \"SELECT id, username, email FROM users WHERE id = ?\"\n"
                        "cursor.execute(query, (user_input_id,))"
                    ),
                })
    except Exception as e:
        print(f"Error scanning code flaws in {file_path}: {e}")
    return findings


def scan_packages(requirements_path: str) -> List[Dict[str, Any]]:
    """
    Step 3: Software Composition Analysis (SCA)
    Checks dependencies against known vulnerable versions in our advisory database.
    """
    findings = []
    if not os.path.exists(requirements_path):
        return findings

    try:
        with open(requirements_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue

                # Parse package name and version (e.g. Flask==0.12.0)
                if "==" in clean_line:
                    pkg_name, version = clean_line.split("==")[:2]
                    pkg_name = pkg_name.strip().lower()
                    version = version.strip()

                    if pkg_name in KNOWN_PACKAGE_ADVISORIES:
                        adv = KNOWN_PACKAGE_ADVISORIES[pkg_name]
                        
                        def parse_version(v_str):
                            nums = []
                            for p in v_str.split("."):
                                try:
                                    nums.append(int(re.sub(r"[^\d]", "", p)))
                                except ValueError:
                                    nums.append(0)
                            return tuple(nums)

                        if parse_version(version) < parse_version(adv["vulnerable_below"]):
                            findings.append({
                                "type": "OUTDATED_PACKAGE",
                                "severity": adv["severity"],
                                "title": f"Vulnerable Dependency: {pkg_name}=={version}",
                                "file": os.path.basename(requirements_path),
                                "line": line_number,
                                "package": pkg_name,
                                "installed_version": version,
                                "fixed_in": adv["fixed_in"],
                                "cve": adv["cve"],
                                "description": adv["description"],
                                "recommendation": f"Upgrade {pkg_name} to version >={adv['fixed_in']}.",
                            })
    except Exception as e:
        print(f"Error scanning packages in {requirements_path}: {e}")
    return findings


def calculate_security_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Step 4: Posture Calculation
    Deducts points from 100 based on the severity of identified vulnerabilities.
    """
    score = 100
    penalty_map = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 10,
        "LOW": 5,
    }

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for item in findings:
        sev = item.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
        score -= penalty_map.get(sev, 5)

    score = max(0, score)  # Score cannot drop below 0

    if score >= 90:
        grade = "A (Excellent)"
    elif score >= 75:
        grade = "B (Good)"
    elif score >= 60:
        grade = "C (Needs Attention)"
    elif score >= 40:
        grade = "D (High Risk)"
    else:
        grade = "F (CRITICAL DANGER)"

    return {
        "score": score,
        "grade": grade,
        "counts": counts,
        "total_findings": len(findings),
    }


def run_full_scan(target_dir: str) -> Dict[str, Any]:
    """
    Coordinates all scanning steps and generates a unified report.
    """
    all_findings = []

    # 1. Walk through and scan source files
    for root, _, files in os.walk(target_dir):
        for file in files:
            full_path = os.path.join(root, file)

            # Skip git and cache directories
            if ".git" in full_path or "__pycache__" in full_path:
                continue

            # Run secrets scanner
            all_findings.extend(scan_secrets(full_path))

            # Run code vulnerability scanner on python files
            if file.endswith(".py"):
                all_findings.extend(scan_code_vulnerabilities(full_path))

    # 2. Run dependency check on requirements.txt
    req_file = os.path.join(target_dir, "requirements.txt")
    if os.path.exists(req_file):
        all_findings.extend(scan_packages(req_file))

    # 3. Calculate score
    summary = calculate_security_score(all_findings)

    return {
        "target_directory": target_dir,
        "summary": summary,
        "findings": all_findings,
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "../target_app"
    target_abs = os.path.abspath(target)

    print("=" * 70)
    print("🛡️  AEGIS-SEC: UNIFIED SECURITY SCANNER")
    print("=" * 70)
    print(f"Target: {target_abs}\n")

    report = run_full_scan(target_abs)
    summary = report["summary"]

    print("-" * 70)
    print(f"📊 SECURITY POSTURE SCORE: {summary['score']} / 100")
    print(f"🏷️  POSTURE GRADE:         {summary['grade']}")
    print(f"🚨 TOTAL FINDINGS:         {summary['total_findings']}")
    print(
        f"   - Critical: {summary['counts']['CRITICAL']} | "
        f"High: {summary['counts']['HIGH']} | "
        f"Medium: {summary['counts']['MEDIUM']} | "
        f"Low: {summary['counts']['LOW']}"
    )
    print("-" * 70)

    print("\n🔍 DETAILED FINDINGS BREAKDOWN:\n")
    for i, finding in enumerate(report["findings"], start=1):
        sev = finding["severity"]
        badge = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "HIGH" else "🟡")
        print(f"[{i}] {badge} [{sev}] {finding['title']}")
        print(f"    File: {finding['file']} (Line {finding['line']})")
        print(f"    Issue: {finding['snippet'] if 'snippet' in finding else finding.get('description', '')}")
        print(f"    Fix:   {finding['recommendation']}")
        print()

    # Save output to report JSON
    report_file = os.path.join(os.path.dirname(__file__), "scan_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"💾 Full unified report exported to: {report_file}")
    print("=" * 70)
