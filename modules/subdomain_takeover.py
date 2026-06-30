#!/usr/bin/env python3
"""
Valkyrie Module: Subdomain Takeover Detector
Author: Sonia
Description: Dangling DNS records detect karta hai jo subdomain takeover
             attacks ke liye exploitable hain (CNAME pointing to unclaimed services).
"""

import aiohttp
import asyncio
import socket
from datetime import datetime

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Valkyrie-TakeoverDetector/2.0"
}

# Fingerprint -> (service_name, severity, cvss)
TAKEOVER_FINGERPRINTS = {
    "There isn't a GitHub Pages site here": ("GitHub Pages", "High", 7.5),
    "NoSuchBucket": ("AWS S3", "High", 8.0),
    "The specified bucket does not exist": ("AWS S3", "High", 8.0),
    "Heroku | No such app": ("Heroku", "High", 7.5),
    "There's nothing here, yet": ("Heroku", "High", 7.5),
    "project not found": ("Surge.sh", "Medium", 6.5),
    "Repository not found": ("GitHub", "Medium", 6.0),
    "No such app": ("Heroku", "High", 7.5),
    "Domain uses Shopify": ("Shopify", "Medium", 5.5),
    "Sorry, this shop is currently unavailable": ("Shopify", "High", 7.0),
    "is not a registered InCloud YouTrack": ("YouTrack", "Medium", 6.0),
    "trying to access your account": ("Pantheon", "Medium", 6.0),
    "Fastly error: unknown domain": ("Fastly", "High", 7.0),
    "page not found": ("Generic 404 - verify manually", "Low", 3.0),
    "404 Not Found": ("Generic 404 - verify manually", "Low", 3.0),
    "The feed you are trying to view": ("Help Scout", "Medium", 6.0),
    "doesn't exist on Tumblr": ("Tumblr", "Medium", 6.0),
    "Do you want to register": ("Webflow", "Medium", 6.0),
    "This UserVoice subdomain is currently available!": ("UserVoice", "High", 7.0),
}

# Common subdomain prefixes for enumeration
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "blog", "shop", "dev", "staging",
    "test", "api", "admin", "portal", "cdn", "static", "assets",
    "app", "demo", "beta", "support", "help", "docs", "status"
]


async def _check_dns_resolves(hostname: str) -> bool:
    """Check karo subdomain DNS resolve karta hai ya nahi."""
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, socket.gethostbyname, hostname)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False


async def _check_takeover_fingerprint(url: str, session: aiohttp.ClientSession) -> dict:
    """Ek subdomain pe takeover fingerprints check karo."""
    try:
        async with session.get(
            url, headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=8), ssl=False,
            allow_redirects=True
        ) as response:
            body = await response.text(errors='ignore')

            for fingerprint, (service, severity, cvss) in TAKEOVER_FINGERPRINTS.items():
                if fingerprint.lower() in body.lower():
                    return {
                        "url": url,
                        "service": service,
                        "severity": severity,
                        "cvss": cvss,
                        "fingerprint": fingerprint,
                        "status_code": response.status
                    }
    except Exception:
        pass

    return None


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    """
    Valkyrie Module: Subdomain takeover scanner.
    Note: Yeh module current target aur common subdomain variations check karta hai.
    Full subdomain enumeration ke liye subfinder/amass jaisa dedicated tool use karo.
    """
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        return {"status": "Tampered", "summary": "Module integrity violation detected."}

    base_domain = target_url.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0]
    # www. hatao agar already hai to root domain milay
    if base_domain.startswith("www."):
        base_domain = base_domain[4:]

    findings = []
    checked_count = 0

    try:
        # Common subdomains generate karo aur check karo
        tasks_to_check = []
        for prefix in COMMON_SUBDOMAINS[:10]:  # Limit to avoid too many DNS queries
            subdomain = f"{prefix}.{base_domain}"
            tasks_to_check.append(subdomain)

        for subdomain in tasks_to_check:
            checked_count += 1
            resolves = await _check_dns_resolves(subdomain)

            if resolves:
                # DNS resolve hota hai — ab fingerprint check karo
                test_url = f"https://{subdomain}"
                result = await _check_takeover_fingerprint(test_url, session)

                if result:
                    findings.append(result)

            await asyncio.sleep(0.1)

        # Main target ka bhi check karo
        main_result = await _check_takeover_fingerprint(target_url, session)
        if main_result:
            findings.append(main_result)

    except Exception as e:
        return {
            "status": "Error",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"Subdomain takeover scanner error: {str(e)}"
        }

    if findings:
        max_cvss = max(f["cvss"] for f in findings)
        details = []
        for f in findings:
            details.append(
                f"[{f['severity']}] {f['url']} — Possible {f['service']} takeover "
                f"(fingerprint: '{f['fingerprint']}')"
            )

        return {
            "status": "Vulnerable / Alert",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": (
                f"🌍 SUBDOMAIN TAKEOVER RISK — {len(findings)} finding(s)! Max CVSS: {max_cvss}\n" +
                "\n".join(details)
            )
        }

    return {
        "status": "Safe / Clean",
        "timestamp": datetime.utcnow().isoformat(),
        "summary": f"No subdomain takeover risk found. Checked {checked_count} common subdomains."
    }


# Backward compatibility — sync wrapper
def check_takeover(url: str) -> str:
    async def _run():
        async with aiohttp.ClientSession() as session:
            result = await run(url, session)
            return result["summary"]
    return asyncio.run(_run())


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
        print(f"\n[*] Subdomain takeover scanning: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())

