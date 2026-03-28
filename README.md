# BugShikari

<p align="center">
  <img src="https://img.shields.io/badge/Beginner-Friendly-green.svg" alt="Beginner Friendly">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Status-Active-red.svg" alt="Status">
</p>

BugShikari is a Python-based automated reconnaissance and web security scanning toolkit.
It helps bug hunters and security researchers collect findings faster and convert them into
detailed HTML reports that are easier to review and submit.

## Table of Contents

- [What This Project Does](#what-this-project-does)
- [Why BugShikari](#why-bugshikari)
- [How It Works](#how-it-works)
- [Modules Included](#modules-included)
- [Installation](#installation)
- [Usage](#usage)
- [Quick Demo](#quick-demo)
- [Project Links](#project-links)
- [Cookies: Missing or Wrong Cookies](#cookies-missing-or-wrong-cookies)
- [Important Legal Note](#important-legal-note)
- [Disclaimer](#disclaimer)

## What This Project Does

Think of BugShikari like a security assistant for target domains:

- It discovers attack surface (subdomains, ports, technologies, content paths).
- It checks common web security misconfigurations.
- It analyzes JavaScript files for secrets/endpoints and related risk context.
- It combines all saved module outputs into a single HTML report.

## Why BugShikari

- Beginner-friendly workflow: simple CLI and interactive mode.
- Fast triage: severity-based findings and categorized output.
- Modular scans: run one module or full scan depending on your need.
- Reusable reporting: generate report again from existing JSON results.

## How It Works

1. **Target normalization**: input like `https://example.com/path` is sanitized.
2. **Module execution**: selected modules run and save JSON in `results/`.
3. **Evidence mapping**: report engine reads JSON and builds finding sections.
4. **HTML reporting**: one final report is generated with summaries and details.

## Modules Included

1. Subdomain Enumeration
2. HTTP Header Analyzer
3. CSP Analyzer
4. Technology Fingerprinting
5. Google Dork Generator
6. CORS Scanner
7. JavaScript Analyzer
8. Open Redirect Scanner
9. Port Scanner
10. Content Discovery

## Installation

1. Clone the repository.
2. Install dependencies.

```powershell
git clone https://github.com/yourusername/BugShikari.git
cd BugShikari
pip install -r requirements.txt
```

## Usage

### Run all scan modules for a target

```powershell
python main.py --target example.com
```

### Run a specific module

```powershell
python main.py --target example.com --module 8
```

### Interactive mode

```powershell
python main.py
```

### Generate report only (from existing JSON results)

```powershell
python main.py --report
```

After report generation, open the latest report file from `results/`, for example:
`report_example_com_YYYYMMDD_HHMMSS.html`.

## Quick Demo

Run a full scan and generate report:

```powershell
python main.py --target example.com
```

Run only JavaScript analysis:

```powershell
python main.py --target example.com --module 7
```

Generate HTML report from already saved JSON results:

```powershell
python main.py --report
```

## Project Links

- Repository: `https://github.com/RITURAJRAMAN/BugShikari`
- Issues: `https://github.com/RITURAJRAMAN/BugShikari/issues`

## Cookies: Missing or Wrong Cookies

If a module needs authenticated access and cookies are missing/invalid:

- Public endpoints still scan normally.
- Auth-only pages may return redirect/login/403 and produce limited findings.
- Results can include false negatives for protected areas.

Recommendation: use cookies that belong to the same target domain and valid session scope.

## Important Legal Note

Use BugShikari only on assets you own or where you have explicit permission to test.
Unauthorized scanning can violate law and platform policies.

## Disclaimer

This toolkit produces **automated scan output**, not a manual penetration test report.
Always validate findings manually before disclosure/submission.

---

BugShikari by Rituraj Raman

Make the web safer, one bug at a time.
