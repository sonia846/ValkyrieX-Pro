#!/usr/bin/env python3
"""
Valkyrie Module: Open Redirect Scanner
Author: Sonia
Description: URL redirection vulnerabilities detect karta hai jo
             phishing attacks ke liye exploit ho sakti hain.
"""

import aiohttp
import asyncio
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from datetime import datetime

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

# Malicious redirect target jo test karenge
EVIL_DOMAIN = "evil-attacker-valkyrie.com"

REDIRECT_PAYLOADS = [
    f"https://{EVIL_DOMAIN}",
    f"//{EVIL_DOMAIN}",
    f"https:{EVIL_DOMAIN}",
    f"/\\{EVIL_DOMAIN}",
    f"https://{EVIL_DOMAIN}/%2e%2e",
    f"https://target.com.{EVIL_DOMAIN}",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "url", "next",
    "return", "returnUrl", "return_url", "goto", "dest",
    "destination", "continue", "target", "link", "out"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Valkyrie-RedirectScanner/2.0"
}


def _build_test_urls(target_url: str, payload: str) -> list:
    parsed = urlparse(target_url)
    test_urls = []

    existing_params = parse_qsl(parsed.query)
    if existing_params:
        injected = [(k, payload) for k, v in existing_params]
        new_query = urlencode(injected)
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        test_urls.append(test_url)

    for param in REDIRECT_PARAMS[:6]:
        new_query = urlencode([(param, payload)])
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        test_urls.append(test_url)

    return test_urls


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    """
    Valkyrie Module: Open Redirect scanner.
    """
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        return {"status": "Tampered", "summary": "Module integrity violation detected."}

    findings = []
    tested_count = 0

    try:
        for payload in REDIRECT_PAYLOADS:
            test_urls = _build_test_urls(target_url, payload)

            for test_url in test_urls[:4]:
                try:
                    async with session.get(
                        test_url,
                        headers=HEADERS,
                        timeout=aiohttp.ClientTimeout(total=8),
                        ssl=False,
                        allow_redirects=False  # IMPORTANT: redirect follow mat karo
                    ) as response:

                        tested_count += 1

                        # 3xx response with Location header check karo
                        if response.status in (301, 302, 303, 307, 308):
                            location = response.headers.get("Location", "")

                            if EVIL_DOMAIN in location:
                                findings.append({
                                    "payload": payload,
                                    "url": test_url,
                                    "redirects_to": location,
                                    "status_code": response.status
                                })
                                break

                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue

            await asyncio.sleep(0.2)

    except Exception as e:
        return {
            "status": "Error",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"Open redirect scanner error: {str(e)}"
        }

    if findings:
        details = []
        for f in findings:
            details.append(
                f"PAYLOAD: {f['payload']} | URL: {f['url']} | "
                f"REDIRECTS TO: {f['redirects_to']} | Status: {f['status_code']}"
            )

        return {
            "status": "Vulnerable / Alert",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": (
                f"↪️ OPEN REDIRECT DETECTED — {len(findings)} finding(s)! "
                f"Can be used for phishing attacks.\n" +
                "\n".join(details)
            )
        }

    return {
        "status": "Safe / Clean",
        "timestamp": datetime.utcnow().isoformat(),
        "summary": f"No open redirect found. Tested {tested_count} parameter combinations."
    }


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
        print(f"\n[*] Open redirect testing: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())
