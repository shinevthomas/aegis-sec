# 🛡️ AegisSec: Unified Application Security Posture Management (ASPM)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security Posture](https://img.shields.io/badge/Posture%20Score-100%2F100-emerald.svg)]()

> A developer-friendly Application Security Posture Management (ASPM) platform that orchestrates secret scanning, static code analysis (SAST), and dependency vulnerability auditing (SCA) into a single unified control room.

---

## 📌 Problem & Motivation

Enterprise development teams face **alert fatigue**—juggling separate reports from distinct tools for leaked keys, code bugs, and vulnerable packages. 

**AegisSec** solves this by:
1. **Aggregating multi-source security telemetry** into a normalized schema.
2. **Scoring repository security posture** (0–100 with letter grading).
3. **Providing actionable inline code diffs** so developers can remediate findings in minutes.

---

## 🏗️ Architecture & Engines

```
[ Target Codebase ]
         │
         ▼
[ AegisSec Scanner Engine ]
  ├── 1. Secrets Scanner (Gitleaks-style pattern & entropy matching)
  ├── 2. Code Vulnerability / SAST (Semgrep-style AST/query analysis)
  └── 3. Dependency Inspector / SCA (Trivy-style advisory matching)
         │
         ▼
[ Unified Posture Normalizer ] ──> [ scan_report.json ]
         │
         ▼
[ AegisSec Web Control Room ] (http://localhost:8080)
```

### 1. Secrets Scanner (Gitleaks Engine)
- Scans source trees using regex signatures for AWS IAM access keys, Stripe live tokens, GitHub tokens, and high-entropy credentials.
- Masks sensitive values in outputs to prevent log leakage.

### 2. Static Code Analysis (Semgrep SAST Engine)
- Analyzes syntax structures for dangerous patterns, specifically flagging SQL Injection (CWE-89) in database access routines and suggesting parameterized alternatives.

### 3. Software Composition Analysis (Trivy SCA Engine)
- Parses `requirements.txt` / dependencies and cross-references known vulnerability advisory databases (CVEs).

---

## 🚀 Quickstart

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/aegis-sec.git
cd aegis-sec
```

### 2. Run the Scanner (CLI)
```bash
python3 engine/scanner.py target_app
```

### 3. Launch the Web Dashboard
```bash
python3 dashboard/server.py
```
Open **`http://localhost:8080`** in your browser.

---

## 📊 Live Control Room Features

- **Executive KPI Cards:** Instant visibility into Posture Score, Total Findings, and Critical Risk counts.
- **Filterable Triage:** Filter by `Secrets`, `Code Flaws`, or `Dependencies`.
- **Developer Remediation Diff:** Inline copyable code patches for immediate fixes.
- **On-Demand Rescan:** One-click re-evaluation via REST API.

---

## 📄 License
This project is licensed under the MIT License.
