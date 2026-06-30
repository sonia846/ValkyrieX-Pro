#!/usr/bin/env python3
"""
Valkyrie Module: CRLF Injection Tester
Author: Sonia
Description: HTTP header injection (CRLF) vulnerabilities detect karta hai
             jo response splitting aur header injection attacks ke liye exploit hoti hain.
"""

import aiohttp
import asyncio
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from datetime import datetime

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

# CRLF payloads — various encoding bypass techniques
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:valkyrie_crlf=1",
    "%0d%0aX-Injected-Header:valkyrie_crlf",
    "\r\nSet-Cookie:valkyrie_crlf=1",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%E5%98%8A%E5%98%8DSet-Cookie:valkyrie_crlf=1",  # Unicode bypass
    "%23%0d%0aSet-Cookie:valkyrie_crlf=1",
]

INJECT_PARAMS = [
    "redirect", "url", "next", "return", "path", "page", "ref"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Valkyrie-CRLFTester/2.0"
}

MARKER = "valkyrie_crlf"


def _build_test_urls(target_url: str, payload: str) -> list:
    parsed = urlparse(target_url)
    test_urls = []

    existing_params = parse_qsl(parsed.query)
    if existing_params:
        injected = [(k, payload) for k, v in existing_params]
        new_query = urlencode(injected, safe='%')
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        test_urls.append(test_url)

    for param in INJECT_PARAMS[:4]:
        new_query = urlencode([(param, payload)], safe='%')
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        test_urls.append(test_url)

    return test_urls


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    """
    Valkyrie Module: CRLF Injection scanner.
    """
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        return {"status": "Tampered", "summary": "Module integrity violation detected."}

    findings = []
    tested_count = 0

    try:
        for payload in CRLF_PAYLOADS:
            test_urls = _build_test_urls(target_url, payload)

            for test_url in test_urls[:3]:
                try:
                    async with session.get(
                        test_url,
                        headers=HEADERS,
                        timeout=aiohttp.ClientTimeout(total=8),
                        ssl=False,
                        allow_redirects=False
                    ) as response:

                        tested_count += 1

                        # Check karo agar injected header response mein aaya
                        injected_header_found = False
                        for header_name, header_value in response.headers.items():
                            if MARKER in header_value.lower() or MARKER in header_name.lower():
                                injected_header_found = True
                                break

                        # Set-Cookie header specifically check karo
                        set_cookie = response.headers.get("Set-Cookie", "")
                        if MARKER in set_cookie.lower():
                            injected_header_found = True

                        if injected_header_found:
                            findings.append({
                                "payload": payload,
                                "url": test_url,
                                "status_code": response.status,
                                "evidence": "Injected header/cookie reflected in response"
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
            "summary": f"CRLF tester error: {str(e)}"
        }

    if findings:
        details = []
        for f in findings:
            details.append(
                f"PAYLOAD: {f['payload']} | URL: {f['url']} | "
                f"EVIDENCE: {f['evidence']}"
            )

        return {
            "status": "Vulnerable / Alert",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": (
                f"📝 CRLF INJECTION DETECTED — {len(findings)} finding(s)! "
                f"HTTP response splitting possible.\n" +
                "\n".join(details)
            )
        }

    return {
        "status": "Safe / Clean",
        "timestamp": datetime.utcnow().isoformat(),
        "summary": f"No CRLF injection found. Tested {tested_count} parameter combinations."
    }


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
        print(f"\n[*] CRLF testing: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())
