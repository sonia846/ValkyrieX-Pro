# 🛡️ ValkyrieX Pro

<div align="center">

**AI-Powered Bug Bounty Hunter**

👩‍💻 **Author & Developer: Sonia** 🇵🇰 | UAE 🇦🇪

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple?style=for-the-badge&logo=linux&logoColor=white)](https://kali.org)
[![HackerOne](https://img.shields.io/badge/HackerOne-Ready-orange?style=for-the-badge)](https://hackerone.com)
[![Author](https://img.shields.io/badge/Author-Sonia-ff69b4?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

> *"Finding what others miss — one vulnerability at a time."*

---

⚠️ **This tool is the exclusive intellectual property of Sonia.**
Unauthorized execution or distribution is strictly prohibited.
Tool contains integrity locks — only Sonia can run it.

</div>

---

## 📖 Table of Contents

- [✨ Features](#-features)
- [🗂️ Project Structure](#️-project-structure)
- [⚙️ Installation](#️-installation)
- [🚀 How To Run](#-how-to-run)
- [🧠 AI Engine](#-ai-engine)
- [📊 Reports](#-reports)
- [🎯 Bug Bounty Tips](#-bug-bounty-tips)
- [⚖️ Legal Notice](#️-legal-notice)

---

## ✨ Features

| 🔍 Feature | 📋 Details |
|-----------|-----------|
| 🐛 13 Scanning Modules | XSS, SQLi, Ports, Headers & more |
| 🧠 AI-Powered Analysis | Gemini AI removes false positives |
| 📊 Auto Report Generator | TXT + HTML + JSON + DOCX |
| 🎯 HackerOne Ready | Formatted reports for submission |
| 🔒 Integrity Protection | Locked to author Sonia only |
| ⚡ Async Engine | High-speed parallel scanning |
| 🛡️ WAF Detection | Firewall fingerprinting |

---

## 💰 Modules & Bounty Potential

| Module | What It Finds | Bounty Range |
|--------|--------------|-------------|
| 🐛 XSS Scanner | Reflected Cross-Site Scripting | $100 - $2,000 |
| 💉 SQLi Scanner | SQL Injection (Error + Time-Based) | $500 - $5,000 |
| 🔌 Port Scanner | Open Services & Banners | $200 - $1,000 |
| 📁 Dir Bruteforcer | Hidden Files & Endpoints | $100 - $2,000 |
| 🔑 Secret Hunter | Exposed API Keys & .env Files | $500 - $5,000 |
| 📋 Header Auditor | Missing Security Headers | $50 - $500 |
| 🌐 CORS Auditor | CORS Misconfigurations | $200 - $1,000 |
| 🔒 SSL Auditor | SSL/TLS Weaknesses | $100 - $500 |
| ↪️ Open Redirect | URL Redirection Bugs | $100 - $500 |
| 📝 CRLF Tester | Header Injection | $200 - $1,000 |
| 🎫 JWT Analyzer | Token Security Flaws | $500 - $3,000 |
| 🌍 Subdomain Takeover | Dangling DNS Records | $500 - $5,000 |
| 🛡️ WAF Detector | Firewall Fingerprinting | Info |

---

## 🗂️ Project Structure

```
ValkyrieX-Pro/
│
├── 📄 README.md
├── 🚀 main.py                  ← Master launcher
├── ⚙️  config.json             ← Settings & API keys
├── 📦 requirements.txt
│
├── 🧠 ai_engine/
│   ├── analyzer.py             ← Gemini AI analyzer
│   └── report_writer.py        ← Auto report generator
│
├── 🔍 modules/                 ← 13 scanning modules
│   ├── xss_scanner.py
│   ├── sqli_scanner.py
│   ├── port_scanner.py
│   ├── dir_bruteforcer.py
│   └── ... (9 more)
│
└── 📊 reports/
    ├── output/                 ← HTML reports
    ├── txt/                    ← Text reports
    ├── json/                   ← JSON reports
    └── docx/                   ← Word reports
```

---

## ⚙️ Installation

### Step 1 — Clone Repository
```bash
git clone https://github.com/sonia846/ValkyrieX-Pro.git
cd ValkyrieX-Pro
```

### Step 2 — Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3 — Add Your Gemini API Key
```bash
nano config.json
# "gemini_api_key": "YOUR_KEY_HERE"
```
Get free key: https://aistudio.google.com

### Step 4 — Permission
```bash
chmod +x main.py
```

---

## 🚀 How To Run

```bash
# Basic scan
python3 main.py https://target.com

# With AI analysis
python3 main.py https://target.com --ai

# Specific module only
python3 main.py https://target.com --module xss_scanner
python3 main.py https://target.com --module sqli_scanner

# Choose report format
python3 main.py https://target.com --report all
python3 main.py https://target.com --report html
python3 main.py https://target.com --report txt
```

### 🧪 Safe Practice Targets
```bash
# These are intentionally vulnerable — safe to test!
python3 main.py http://testphp.vulnweb.com
python3 main.py http://testphp.vulnweb.com/listproducts.php?cat=1
```

---

## 🧠 AI Engine

ValkyrieX Pro uses **Google Gemini AI** to analyze results:

```
Raw Scan Output
      ↓
🧠 Gemini AI
      ↓
✅ False positives removed
📊 CVSS score assigned
🎯 P1 / P2 / P3 / P4 severity
📝 Exploitation steps written
💡 Remediation suggested
      ↓
HackerOne-Ready Report 🎉
```

---

## 📊 Reports

Every scan auto-generates reports in 4 formats:

```
reports/
├── output/   sonia_target_2024-01-01.html  ← Beautiful HTML
├── txt/      sonia_target_2024-01-01.txt   ← Plain text
├── json/     sonia_target_2024-01-01.json  ← Raw data
└── docx/     sonia_target_2024-01-01.docx  ← Word document
```

---

## 🎯 Bug Bounty Tips

> 💡 **Pro Tips for Earning $1000+**

1. ✅ Always check program **scope** first
2. ✅ Focus on **P1/P2** (Critical & High) bugs
3. ✅ **Combine bugs** for higher impact
4. ✅ Write **clear, detailed** reports with PoC
5. ✅ Test programs with **high bounties**
6. ✅ Practice on **HackTheBox** before real targets

**Recommended Programs for Beginners:**
- 🔸 HackerOne Public Programs
- 🔸 Talabat (UAE based)
- 🔸 Careem (UAE based)
- 🔸 Bugcrowd University

---

## ⚖️ Legal Notice

> ⚠️ **FOR AUTHORIZED SECURITY TESTING ONLY**
>
> - Only test targets you have **written permission** for
> - Always check bug bounty program **scope**
> - Unauthorized use is **illegal** worldwide
> - Developer holds no responsibility for misuse

---

<div align="center">

Made with ❤️ by **Sonia** 🇵🇰

*ValkyrieX Pro — Because every bug tells a story* 🛡️

</div>
