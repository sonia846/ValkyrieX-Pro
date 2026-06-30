#!/usr/bin/env python3
"""
Valkyrie 20-in-1 Framework - Async Directory Bruteforcer Module
Author: Sonia
Description: Asynchronous web directory fuzzer to discover hidden paths and endpoints.
"""

import aiohttp
import asyncio
import logging
from datetime import datetime

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "wp-admin", "administrator",
    "backup", "config", "db", "backups", "uploads",
    "images", "css", "js", "assets", "static",
    "api", "v1", "v2", "api/v1", "api/v2",
    "robots.txt", "sitemap.xml", ".env", ".git/config", "composer.json",
    "phpinfo.php", "info.php", "test.php", "shell.php",
    "phpmyadmin", "pma", "mysql", "cpanel", "webmail",
    "server-status", "server-info", "wp-content", "wp-includes",
    "plugins", "themes", "vendor", "node_modules", "storage",
    "logs", "error.log", "access.log", "debug.log",
    "swagger", "swagger-ui", "docs", "documentation",
    "graphql", "graphiql", "soap", "wsdl",
    "index.php", "index.html", "index.htm", "default.aspx",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "health", "healthcheck", "status", "ping",
    ".htaccess", "web.config", "Dockerfile",
    "package.json", "requirements.txt", "README.md",
    "api/users", "api/admin", "api/config",
    "forgot-password", "reset-password", "change-password",
    "oauth/token", "auth/login", "auth/register",
    "internal", "private", "secret", "hidden",
    "dump.sql", "backup.zip", "backup.tar.gz"
]

CRITICAL_PATHS = {
    '.env', '.git/config', 'shell.php', 'phpinfo.php',
    'wp-config.php', 'composer.json', 'error.log',
    'dump.sql', 'backup.zip', 'backup.tar.gz'
}


async def check_path(target_url: str, path: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore) -> dict:
    """Single path ko check karta hai async get request se."""
    async with semaphore:
        base = target_url.rstrip('/')
        full_url = f"{base}/{path.lstrip('/')}"

        try:
            async with session.get(full_url, timeout=5, ssl=False,
                                 headers={"User-Agent": "Valkyrie-Framework/4.0"}) as resp:
                status = resp.status
                body = await resp.text()
                size = len(body)
                return {"path": path, "url": full_url, "status": status, "size": size}
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return {"path": path, "url": full_url, "status": 0, "size": 0}
        except Exception:
            return {"path": path, "url": full_url, "status": -1, "size": 0}


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    """
    Valkyrie Module: Directory bruteforcer jo hidden paths discovery karta hai.
    """
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        return {"status": "Tampered", "summary": "Module integrity violation detected."}

    semaphore = asyncio.Semaphore(20)

    # Baseline check — false positive filter ke liye (custom 404 pages)
    baseline = await check_path(target_url, "valkyrie_fake_path_xyz123", session, semaphore)
    baseline_size = baseline["size"]

    tasks = [check_path(target_url, path, session, semaphore) for path in DEFAULT_WORDLIST]
    results = await asyncio.gather(*tasks)

    interesting = []
    for r in results:
        if r["status"] in (200, 301, 302, 401, 403, 500):
            # Same size as baseline = fake 200 (custom 404 page) — skip karo
            if r["status"] == 200 and abs(r["size"] - baseline_size) <= 50:
                continue

            if r['path'] in CRITICAL_PATHS and r['status'] == 200:
                r['severity'] = 'CRITICAL'
            elif r['status'] in (200, 301):
                r['severity'] = 'Medium'
            else:
                r['severity'] = 'Low'

            interesting.append(r)

    critical_found = [r for r in interesting if r.get('severity') == 'CRITICAL']

    summary = f"Bruteforced {len(DEFAULT_WORDLIST)} paths — found {len(interesting)} interesting responses."
    if critical_found:
        crit_list = ", ".join([r['path'] for r in critical_found])
        summary += f" 🚨 CRITICAL EXPOSED FILES: {crit_list}"

    return {
        "status": "Vulnerable / Alert" if critical_found else "Completed",
        "timestamp": datetime.utcnow().isoformat(),
        "summary": summary,
        "interesting_paths": interesting[:20]
    }


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
        print(f"\n[*] Directory bruteforcing: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())
