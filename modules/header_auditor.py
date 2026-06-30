#!/usr/bin/env python3
"""
Valkyrie Module: Security Header Auditor
Author: Sonia
Description: HTTP security headers ka audit karta hai aur missing/weak
             headers ko CVSS score ke saath report karta hai.
"""

import aiohttp
import asyncio
from datetime import datetime

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

# Header name -> (severity, cvss_score, description)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Medium", 5.5,
        "Missing Content-Security-Policy (CSP) header. Protection against XSS is reduced."
    ),
    "X-Content-Type-Options": (
        "Low", 3.1,
        "Missing X-Content-Type-Options. Vulnerable to MIME-sniffing attacks."
    ),
    "Strict-Transport-Security": (
        "High", 7.5,
        "Missing Strict-Transport-Security (HSTS). MitM attacks via HTTP downgrade are possible."
    ),
    "X-Frame-Options": (
        "Medium", 5.0,
        "Missing X-Frame-Options. Site is vulnerable to Clickjacking attacks."
    ),
    "Referrer-Policy": (
        "Low", 2.5,
        "Missing Referrer-Policy. Sensitive URL data may leak to third parties."
    ),
    "Permissions-Policy": (
        "Low", 2.0,
        "Missing Permissions-Policy. Browser features not restricted (camera, mic, etc)."
    ),
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Valkyrie-HeaderAuditor/2.0"
}


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    """
    Valkyrie Module: Security headers ko check karta hai.
    """
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        return {"status": "Tampered", "summary": "Module integrity violation detected."}

    try:
        async with session.get(
            target_url,
            headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
            allow_redirects=True
        ) as response:

            response_headers = response.headers
            findings = []
            max_cvss = 0.0

            for header_name, (severity, cvss, description) in SECURITY_HEADERS.items():
                if header_name not in response_headers:
                    findings.append({
                        "header": header_name,
                        "severity": severity,
                        "cvss": cvss,
                        "description": description
                    })
                    max_cvss = max(max_cvss, cvss)

            # Server banner info disclosure check
            server_banner = response_headers.get("Server", "")
            if server_banner:
                findings.append({
                    "header": "Server",
                    "severity": "Low",
                    "cvss": 2.5,
                    "description": f"Server banner leaks software info: {server_banner}"
                })

            if findings:
                details = []
                for f in findings:
                    details.append(
                        f"[{f['severity']}] {f['header']} (CVSS: {f['cvss']}) — {f['description']}"
                    )

                return {
                    "status": "Vulnerable / Alert" if max_cvss >= 7.0 else "Completed",
                    "timestamp": datetime.utcnow().isoformat(),
                    "summary": (
                        f"⚠️ {len(findings)} header issue(s) found. Max CVSS: {max_cvss}\n" +
                        "\n".join(details)
                    )
                }

            return {
                "status": "Safe / Clean",
                "timestamp": datetime.utcnow().isoformat(),
                "summary": "All critical security headers are present and configured."
            }

    except Exception as e:
        return {
            "status": "Error",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"Header audit error: {str(e)}"
        }


# Backward compatibility — sync wrapper
def audit_headers(url: str) -> str:
    async def _run():
        async with aiohttp.ClientSession() as session:
            result = await run(url, session)
            return result["summary"]
    return asyncio.run(_run())


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "https://google.com"
        print(f"\n[*] Header auditing: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())
