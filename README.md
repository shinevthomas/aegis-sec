# 🛡️ AegisSec: Enterprise Application Security Posture Management (ASPM)

[![CI / Security Gate](https://github.com/shinevthomas/aegis-sec/actions/workflows/aegis-security-gate.yml/badge.svg)](https://github.com/shinevthomas/aegis-sec/actions)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Compliant-blueviolet.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/Tests-Passing%20(5%2F5)-success.svg)](https://github.com/shinevthomas/aegis-sec/tree/main/tests)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> An enterprise-grade Application Security Posture Management (ASPM) platform that automates multi-vector vulnerability scanning, enforces CI/CD quality gates, and exports industry-standard **OASIS SARIF 2.1.0** reports for GitHub Advanced Security.

---

## 🏗️ Architectural Overview

```
                          ┌───────────────────────────┐
                          │   Target Code Repository  │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
                  ╔═══════════════════════════════════════════╗
                  ║         AegisSec Scanning Engine          ║
                  ║  ├─ Secrets Detection (Gitleaks-style)   ║
                  ║  ├─ Code Vulnerabilities (Semgrep-style)  ║
                  ║  └─ Dependency SCA (Trivy-style CVEs)     ║
                  ╚═════════════════════╤═════════════════════╝
                                        │
                  ┌─────────────────────┼─────────────────────┐
                  ▼                     ▼                     ▼
        [ CLI Table Report ]    [ OASIS SARIF 2.1.0 ]    [ Posture Score ]
         (Human Readable)       (GitHub CodeQL Spec)     (0–100 & Grade)
                                        │
                                        ▼
        ┌─────────────────────────────────────────────────────────────┐
        │  1. CI/CD Quality Gate (--threshold 80: Pass / Block PR)    │
        │  2. Web Posture Center (http://localhost:8080)             │
        │  3. GitHub Security Tab (Code Scanning Alerts)              │
        └─────────────────────────────────────────────────────────────┘
```

---

## ✨ Enterprise Capabilities

1. **Multi-Vector Threat Detection:**
   * **Secrets Engine:** Signature matching for high-entropy tokens (AWS IAM, Stripe, Private Keys) with automated credential masking in logs.
   * **SAST Engine:** Syntax pattern analysis detecting SQL Injection (CWE-89) and insecure query interpolation.
   * **SCA Engine:** Semver dependency checker cross-referencing public CVE advisories (e.g., CVE-2018-18074, CVE-2019-11324).
2. **Industry-Standard Output (SARIF 2.1.0):**
   * Natively ingested by **GitHub Code Scanning**, Azure DevOps, and SonarQube.
3. **CI/CD Quality Gatekeeper:**
   * Built-in `--threshold <min_score>` flag that triggers exit code `1` to fail CI builds on unacceptable risk.
4. **Automated GitHub Actions:**
   * Fully automated workflow runs on every `push` and `pull_request`, uploading SARIF alerts directly to GitHub Security.
5. **Containerized Deployment:**
   * Production-ready `Dockerfile` and `docker-compose.yml` with non-root security context.

---

## 🚀 Quickstart & Usage

### 1. Run via CLI

```bash
# Standard Table Output
python3 engine/scanner.py target_app

# Enforce a CI/CD Quality Gate (fails if score < 80)
python3 engine/scanner.py target_app --threshold 80

# Export OASIS SARIF 2.1.0 Report
python3 engine/scanner.py target_app --format sarif --output results.sarif
```

### 2. Launch the Web Control Room

```bash
python3 dashboard/server.py
```
Open **`http://localhost:8080`** in your browser.

### 3. Run with Docker Compose

```bash
docker compose up
```

---

## 🧪 Automated Testing

AegisSec includes a unit and security regression test suite validating detection accuracy, credential masking, and SARIF formatting:

```bash
python3 -m unittest discover tests
```

---

## 📂 Repository Structure

```text
aegis-sec/
├── .github/
│   └── workflows/
│       └── aegis-security-gate.yml  # Automated CI/CD pipeline & quality gate
├── dashboard/
│   ├── index.html                   # Dark-mode cybersecurity control room UI
│   └── server.py                    # REST API & static web server
├── engine/
│   ├── scanner.py                   # Core ASPM multi-vector scanning engine
│   └── scan_report.json             # Normalized security telemetry
├── target_app/
│   ├── app.py                       # Secured web service (remediated)
│   └── requirements.txt             # Patched package manifest
├── tests/
│   └── test_scanner.py              # Automated regression test suite
├── Dockerfile                       # Multi-stage Alpine container
├── docker-compose.yml               # Service orchestration
└── README.md                        # Documentation & specifications
```

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.
