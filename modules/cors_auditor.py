#!/usr/bin/env python3
"""
Valkyrie Module: CORS Misconfiguration Auditor
Author: Sonia
Description: Cross-Origin Resource Sharing (CORS) misconfigurations
             detect karta hai jo data leakage ka risk create karte hain.
"""

import aiohttp
import asyncio
from datetime import datetime

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

# Malicious origins jo test karne ke liye use honge
TEST_ORIGINS = [
    "https://evil-attacker.com",
    "null",
    "https://sub.evil-attacker.com",
]

HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Valkyrie-CORSAuditor/2.0"
}


async def _test_origin(target_url: str, origin: str, session: aiohttp.ClientSession) -> dict:
    """Ek specific Origin header ke saath request bhejo aur response check karo."""
    headers = dict(HEADERS_BASE)
    headers["Origin"] = origin

    try:
        async with session.get(
            target_url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=8),
            ssl=False,
            allow_redirects=True
        ) as response:

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            return {
                "origin_tested": origin,
                "acao_value": acao,
                "acac_value": acac,
                "reflects_origin": (acao == origin),
                "wildcard": (acao == "*"),
                "credentials_allowed": (acac.lower() == "true")
            }

    except Exception:
        return None


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    """
    Valkyrie Module: CORS misconfiguration scanner.
    """
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        return {"status": "Tampered", "summary": "Module integrity violation detected."}

    findings = []

    try:
        for origin in TEST_ORIGINS:
            result = await _test_origin(target_url, origin, session)
            if result is None:
                continue

            # CRITICAL: Origin reflect ho raha hai AND credentials allowed
            if result["reflects_origin"] and result["credentials_allowed"]:
                findings.append({
                    "severity": "Critical",
                    "cvss": 8.5,
                    "issue": f"Origin '{origin}' reflected with Allow-Credentials: true",
                    "detail": "Attacker-controlled origin can read authenticated responses — full account takeover possible."
                })

            # HIGH: Wildcard with credentials (browsers usually block this, but worth flagging)
            elif result["wildcard"] and result["credentials_allowed"]:
                findings.append({
                    "severity": "High",
                    "cvss": 7.0,
                    "issue": "Wildcard (*) Origin with Allow-Credentials: true",
                    "detail": "Misconfigured — browsers reject this combo but indicates poor CORS hygiene."
                })

            # MEDIUM: Wildcard origin without credentials
            elif result["wildcard"]:
                findings.append({
                    "severity": "Medium",
                    "cvss": 5.0,
                    "issue": "Wildcard (*) Access-Control-Allow-Origin",
                    "detail": "Any website can read this API's public responses."
                })

            # MEDIUM: Origin reflects without credentials check
            elif result["reflects_origin"]:
                findings.append({
                    "severity": "Medium",
                    "cvss": 5.5,
                    "issue": f"Origin '{origin}' reflected in Access-Control-Allow-Origin",
                    "detail": "Server trusts any origin dynamically — should use a strict allowlist."
                })

            await asyncio.sleep(0.2)

        if findings:
            # Duplicate issues hatao
            seen = set()
            unique_findings = []
            for f in findings:
                if f["issue"] not in seen:
                    seen.add(f["issue"])
                    unique_findings.append(f)

            max_cvss = max(f["cvss"] for f in unique_findings)
            details = [f"[{f['severity']}] {f['issue']} — {f['detail']}" for f in unique_findings]

            return {
                "status": "Vulnerable / Alert" if max_cvss >= 7.0 else "Completed",
                "timestamp": datetime.utcnow().isoformat(),
                "summary": (
                    f"🌐 CORS issues found — Max CVSS: {max_cvss}\n" +
                    "\n".join(details)
                )
            }

        return {
            "status": "Safe / Clean",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": "No CORS misconfigurations detected. Origin validation appears strict."
        }

    except Exception as e:
        return {
            "status": "Error",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"CORS audit error: {str(e)}"
        }


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
        print(f"\n[*] CORS auditing: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())
