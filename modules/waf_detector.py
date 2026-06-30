#!/usr/bin/env python3
"""
Valkyrie Module: WAF (Web Application Firewall) Detector
Author: Sonia
Description: Target ke peeche kaunsi WAF/CDN chal rahi hai detect karta hai —
             yeh bug bounty scanning strategy decide karne mein madad karta hai.
"""

import aiohttp
import asyncio
from datetime import datetime

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Valkyrie-WAFDetector/2.0"
}

# WAF/CDN fingerprints — header name/value patterns
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
        "server": ["cloudflare"],
    },
    "AWS WAF / CloudFront": {
        "headers": ["x-amz-cf-id", "x-amzn-requestid"],
        "server": ["cloudfront", "awselb"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop"],
        "server": ["akamaighost"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri/cloudproxy"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["incapsula"],
    },
    "F5 BIG-IP": {
        "headers": ["x-wa-info", "bigipserver"],
        "server": ["big-ip"],
    },
    "Barracuda": {
        "headers": ["barra_counter_session"],
        "server": ["barracuda"],
    },
    "ModSecurity": {
        "headers": ["mod_security", "x-mod-security"],
        "server": ["mod_security"],
    },
    "Fastly": {
        "headers": ["x-served-by", "x-fastly-request-id"],
        "server": ["fastly"],
    },
    "Vercel": {
        "headers": ["x-vercel-id", "x-vercel-cache"],
        "server": ["vercel"],
    },
}

# Suspicious payload jo WAF ko trigger karega agar present hai
WAF_TRIGGER_PAYLOAD = "?test=<script>alert(1)</script>UNION SELECT"


async def _detect_from_headers(target_url: str, session: aiohttp.ClientSession) -> dict:
    """Normal request bhej kar headers se WAF detect karo."""
    try:
        async with session.get(
            target_url, headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=10), ssl=False,
            allow_redirects=True
        ) as response:

            response_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            server_header = response_headers.get("server", "")

            detected = []
            for waf_name, signatures in WAF_SIGNATURES.items():
                # Header name check
                for sig_header in signatures["headers"]:
                    if sig_header.lower() in response_headers:
                        detected.append(waf_name)
                        break

                # Server header value check
                for sig_server in signatures["server"]:
                    if sig_server.lower() in server_header:
                        if waf_name not in detected:
                            detected.append(waf_name)
                        break

            return {"detected": detected, "status_code": response.status, "server": server_header}

    except Exception as e:
        return {"detected": [], "error": str(e)}


async def _detect_from_trigger(target_url: str, session: aiohttp.ClientSession) -> dict:
    """Malicious payload bhej kar dekho WAF block karta hai ya nahi."""
    test_url = f"{target_url.rstrip('/')}{WAF_TRIGGER_PAYLOAD}"

    try:
        async with session.get(
            test_url, headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=8), ssl=False,
            allow_redirects=True
        ) as response:

            # WAF typically blocks with 403, 406, 419, 429, 503
            waf_block_codes = (403, 406, 419, 429, 503)
            is_blocked = response.status in waf_block_codes

            body = await response.text(errors='ignore')
            block_keywords = ["blocked", "forbidden", "security", "firewall", "waf", "denied"]
            has_block_message = any(kw in body.lower()[:2000] for kw in block_keywords)

            return {
                "blocked": is_blocked or has_block_message,
                "status_code": response.status
            }

    except Exception:
        return {"blocked": False, "status_code": None}


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    """
    Valkyrie Module: WAF detector — informational module, scanning strategy ke liye useful.
    """
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        return {"status": "Tampered", "summary": "Module integrity violation detected."}

    try:
        header_result = await _detect_from_headers(target_url, session)
        await asyncio.sleep(0.3)
        trigger_result = await _detect_from_trigger(target_url, session)

        detected_wafs = header_result.get("detected", [])
        is_blocking = trigger_result.get("blocked", False)

        if detected_wafs or is_blocking:
            summary_parts = []

            if detected_wafs:
                summary_parts.append(f"Detected WAF/CDN: {', '.join(detected_wafs)}")
            else:
                summary_parts.append("WAF fingerprint not identified, but blocking behavior detected")

            if is_blocking:
                summary_parts.append(
                    f"⚠️ Active blocking confirmed (status: {trigger_result.get('status_code')}) — "
                    f"use evasion techniques, slower scan rate, and payload encoding."
                )
            else:
                summary_parts.append("No active blocking observed on test payload — but WAF may still be present.")

            return {
                "status": "Completed",
                "timestamp": datetime.utcnow().isoformat(),
                "summary": " | ".join(summary_parts)
            }

        return {
            "status": "Safe / Clean",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": "No WAF/CDN detected. Target appears to have no firewall protection — proceed with standard scanning."
        }

    except Exception as e:
        return {
            "status": "Error",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"WAF detector error: {str(e)}"
        }


# Backward compatibility — sync wrapper
def detect_waf(url: str) -> str:
    async def _run():
        async with aiohttp.ClientSession() as session:
            result = await run(url, session)
            return result["summary"]
    return asyncio.run(_run())


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "https://google.com"
        print(f"\n[*] WAF detection: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())
