#!/usr/bin/env python3
"""
Valkyrie Module: Secret & API Key Hunter
Author: Sonia
Description: Exposed API keys, tokens, credentials, aur sensitive data
             ko HTML/JS source code mein dhundta hai.
"""

import aiohttp
import asyncio
import re
from datetime import datetime

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Valkyrie-SecretHunter/2.0"
}

# Pattern -> (severity, cvss, description)
SECRET_PATTERNS = {
    "AWS Access Key": (
        re.compile(r'AKIA[0-9A-Z]{16}'),
        "Critical", 9.0, "AWS Access Key ID exposed — can lead to full cloud account compromise."
    ),
    "AWS Secret Key": (
        re.compile(r'(?i)aws_secret_access_key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})'),
        "Critical", 9.5, "AWS Secret Access Key exposed."
    ),
    "Google API Key": (
        re.compile(r'AIza[0-9A-Za-z_-]{35}'),
        "High", 7.5, "Google API Key exposed — may allow abuse of Google services."
    ),
    "Firebase URL": (
        re.compile(r'[a-z0-9-]+\.firebaseio\.com'),
        "Medium", 5.0, "Firebase database URL exposed — check if database rules are public."
    ),
    "Stripe API Key": (
        re.compile(r'(sk|pk)_live_[0-9a-zA-Z]{24,}'),
        "Critical", 9.0, "Stripe Live API Key exposed — financial data at risk."
    ),
    "Generic API Key": (
        re.compile(r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})'),
        "High", 7.0, "Generic API key pattern found in source."
    ),
    "Generic Secret": (
        re.compile(r'(?i)secret["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})'),
        "High", 6.5, "Generic secret/token pattern found in source."
    ),
    "Private Key Header": (
        re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "Critical", 9.5, "Private key material exposed in response."
    ),
    "JWT Secret": (
        re.compile(r'(?i)jwt[_-]?secret["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{8,})'),
        "Critical", 8.5, "JWT signing secret exposed — token forgery possible."
    ),
    "Database Connection String": (
        re.compile(r'(?i)(mongodb|mysql|postgres|postgresql)://[^\s"\']+:[^\s"\']+@[^\s"\']+'),
        "Critical", 9.0, "Database connection string with credentials exposed."
    ),
    "Slack Token": (
        re.compile(r'xox[baprs]-[0-9a-zA-Z-]{10,}'),
        "High", 7.0, "Slack API token exposed."
    ),
    "GitHub Token": (
        re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        "Critical", 8.5, "GitHub personal access token exposed — repo access at risk."
    ),
    "Generic Password Field": (
        re.compile(r'(?i)password["\']?\s*[:=]\s*["\']([^"\'\s]{6,})'),
        "Medium", 5.5, "Hardcoded password pattern found in source."
    ),
}

# Common paths jahan secrets exposed ho sakte hain
SECRET_FILE_PATHS = [
    ".env", ".env.local", ".env.production",
    "config.js", "config.json", "settings.json",
    ".git/config", "wp-config.php", "appsettings.json",
    "credentials.json", "secrets.yml", "secrets.json"
]


def _scan_text_for_secrets(text: str, source: str) -> list:
    """Text content mein secret patterns dhundo."""
    findings = []
    for name, (pattern, severity, cvss, description) in SECRET_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            findings.append({
                "type": name,
                "severity": severity,
                "cvss": cvss,
                "description": description,
                "source": source,
                "match_count": len(matches)
            })
    return findings


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    """
    Valkyrie Module: Secret hunter — exposed credentials dhundta hai.
    """
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        return {"status": "Tampered", "summary": "Module integrity violation detected."}

    all_findings = []
    base = target_url.rstrip('/')

    try:
        # 1. Main page check karo
        try:
            async with session.get(
                target_url, headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=10), ssl=False
            ) as response:
                if response.status == 200:
                    body = await response.text(errors='ignore')
                    findings = _scan_text_for_secrets(body, "main page")
                    all_findings.extend(findings)
        except Exception:
            pass

        # 2. Common secret file paths check karo
        for path in SECRET_FILE_PATHS:
            full_url = f"{base}/{path}"
            try:
                async with session.get(
                    full_url, headers=HEADERS,
                    timeout=aiohttp.ClientTimeout(total=5), ssl=False
                ) as response:
                    if response.status == 200:
                        body = await response.text(errors='ignore')
                        if len(body) > 0 and len(body) < 50000:  # Reasonable file size
                            findings = _scan_text_for_secrets(body, path)
                            if findings:
                                all_findings.extend(findings)
                            else:
                                # File khud hi expose ho rahi hai (even without pattern match)
                                if path in (".env", ".git/config", "credentials.json"):
                                    all_findings.append({
                                        "type": "Sensitive File Exposed",
                                        "severity": "Critical",
                                        "cvss": 8.0,
                                        "description": f"Sensitive file '{path}' is publicly accessible.",
                                        "source": path,
                                        "match_count": 1
                                    })
            except Exception:
                continue

            await asyncio.sleep(0.2)

    except Exception as e:
        return {
            "status": "Error",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"Secret hunter error: {str(e)}"
        }

    if all_findings:
        max_cvss = max(f["cvss"] for f in all_findings)
        details = []
        for f in all_findings:
            details.append(
                f"[{f['severity']}] {f['type']} (found in: {f['source']}) — {f['description']}"
            )

        return {
            "status": "Vulnerable / Alert",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": (
                f"🔑 SECRETS EXPOSED — {len(all_findings)} finding(s)! Max CVSS: {max_cvss}\n" +
                "\n".join(details)
            )
        }

    return {
        "status": "Safe / Clean",
        "timestamp": datetime.utcnow().isoformat(),
        "summary": "No exposed secrets, API keys, or credentials found."
    }


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
        print(f"\n[*] Secret hunting: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())
