---

# Vulnerable & Outdated Python Components Scanner

![GitHub License](https://img.shields.io/github/license/TheOSuite/oXSS)
![Python Version](https://img.shields.io/badge/python-3.13-blue)

A GUI tool to identify vulnerable, outdated, and potentially unsafe Python dependencies using a combination of static analysis, license checks, and other heuristics. Built with Tkinter, it allows scanning via `requirements.txt` or the active environment.

## 📦 Included Modules

The following modules are included and required:

* `scanner.py` – Parses `requirements.txt` and detects installed packages.
* `vuln_checker.py` – Scans for known vulnerabilities in dependencies.
* `license_checker.py` – Checks licenses of installed packages.
* `report.py` – Exports results to CSV, JSON, and HTML formats.

Optional modules:

* `deprecation_checker.py` – Detects use of deprecated packages or APIs.
* `unsafe_code_scanner.py` – Performs static code analysis for insecure patterns.
* `typosquat_detector.py` – Detects possible typosquatting in dependencies.

---

## 🚀 Features

* Load a `requirements.txt` or scan the current environment
* Check for:

  * Known vulnerabilities (CVEs)
  * License risks
  * Deprecated packages
  * Typosquatting
  * Unsafe code using Bandit (if available)
* Export results to CSV, JSON, or HTML
* Multithreaded background scanning
* Modular, extensible design

---

## 🖥️ Usage

### Installation

Make sure you are using Python 3.7 or newer.

1. Clone or download the project folder.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

> Optional: Install Bandit and other tools to enable advanced features:

```bash
pip install bandit
```

3. Run the application:

```bash
python gui.py
```

### Interface Overview

* **Load requirements.txt**: Select a file to scan listed packages.
* **Scan Environment**: Scan currently installed packages (uses `pip freeze`).
* **Scan for Vulnerabilities**: Check packages for known vulnerabilities.
* **Check Licenses**: Identify license types and possible issues.
* **Suggest Updates**: View available newer versions for outdated packages.
* **Check Deprecations**: Detect deprecated packages (if module available).
* **Scan Unsafe Code**: Static analysis for insecure code (if module available).
* **Detect Typosquatting**: Heuristics to detect suspicious package names.

---

## 🗂️ Output

After a scan, results can be exported in multiple formats:

* **CSV**
* **JSON**
* **HTML** (opens in browser)

---

## 🔒 Dependencies

Listed in `requirements.txt`. At minimum:

* `tkinter` (comes with standard Python)
* `requests`
* `packaging`
* `bandit` *(optional, for unsafe code analysis)*

---

## 📁 Project Structure

```
project/
├── gui.py
├── scanner.py
├── vuln_checker.py
├── license_checker.py
├── report.py
├── deprecation_checker.py      # optional
├── unsafe_code_scanner.py      # optional
├── typosquat_detector.py       # optional
├── requirements.txt
```

---

## ❓FAQ

**Q: Some buttons are disabled or say "Module Missing." Why?**
A: Those features depend on optional modules. Install them or include them in the project directory.

**Q: Can I use this as a CLI tool?**
A: Not yet. This is designed as a GUI-first tool, but modular functions may be reused in CLI contexts.

---

## ✅ Future Features

* CLI interface
* Auto-fix or suggestions for insecure code
* Integration with `pip-audit` or `Safety`

---
