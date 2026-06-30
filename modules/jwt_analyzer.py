#!/usr/bin/env python3
"""
Valkyrie Module: JWT Security Analyzer
Author: Sonia
Description: JSON Web Tokens (JWT) mein security flaws detect karta hai —
             weak algorithms, none algorithm bypass, expired tokens, etc.
"""

import aiohttp
import asyncio
import json
import base64
import re
from datetime import datetime, timezone

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Valkyrie-JWTAnalyzer/2.0"
}

# Common cookie/header names jahan JWT milte hain
JWT_LOCATIONS = ["Authorization", "Set-Cookie", "X-Auth-Token", "token"]

JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


def _b64_decode(data: str) -> dict:
    """JWT segment ko base64 decode karo (padding fix ke saath)."""
    try:
        padding = '=' * (4 - len(data) % 4)
        decoded = base64.urlsafe_b64decode(data + padding)
        return json.loads(decoded)
    except Exception:
        return {}


def _analyze_jwt(token: str) -> list:
    """Ek JWT token ko analyze karke security issues dhundo."""
    findings = []

    parts = token.split('.')
    if len(parts) != 3:
        return findings

    header = _b64_decode(parts[0])
    payload = _b64_decode(parts[1])
    signature = parts[2]

    if not header:
        return findings

    alg = header.get('alg', '').lower()

    # CRITICAL: "none" algorithm — signature verification bypass
    if alg == 'none':
        findings.append({
            "severity": "Critical",
            "cvss": 9.5,
            "issue": "JWT uses 'none' algorithm",
            "detail": "Signature verification can be completely bypassed — full auth bypass possible."
        })

    # HIGH: Weak algorithm
    elif alg in ('hs256',) and not signature:
        findings.append({
            "severity": "High",
            "cvss": 7.5,
            "issue": "JWT missing signature with HS256",
            "detail": "Token has no signature — verification likely not enforced server-side."
        })

    # MEDIUM: Algorithm confusion risk (RS256 -> HS256 attack surface)
    if alg == 'rs256':
        findings.append({
            "severity": "Info",
            "cvss": 0.0,
            "issue": "JWT uses RS256 — check for algorithm confusion vulnerability",
            "detail": "Manually test if server accepts HS256 with public key as secret (alg confusion attack)."
        })

    # Expiry check
    if 'exp' in payload:
        try:
            exp_time = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
            if exp_time < datetime.now(timezone.utc):
                findings.append({
                    "severity": "Medium",
                    "cvss": 5.0,
                    "issue": "JWT token expired but possibly still accepted",
                    "detail": f"Token expired at {exp_time.isoformat()} — verify server rejects it."
                })
        except Exception:
            pass

    # No expiry set — token never expires
    if 'exp' not in payload:
        findings.append({
            "severity": "Medium",
            "cvss": 5.5,
            "issue": "JWT has no expiration (exp claim missing)",
            "detail": "Token never expires — if leaked, attacker has permanent access."
        })

    # Sensitive data in payload check
    sensitive_keys = ['password', 'secret', 'ssn', 'credit_card', 'api_key']
    for key in payload.keys():
        if any(s in key.lower() for s in sensitive_keys):
            findings.append({
                "severity": "High",
                "cvss": 6.5,
                "issue": f"Sensitive data in JWT payload: '{key}'",
                "detail": "JWT payload is base64 encoded, NOT encrypted — anyone can read this data."
            })

    return findings


async def run(target_url: str, session: aiohttp.ClientSession) -> dict:
    """
    Valkyrie Module: JWT analyzer — target se JWT tokens dhundta hai aur analyze karta hai.
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

            body = await response.text(errors='ignore')
            all_headers_text = " ".join([f"{k}: {v}" for k, v in response.headers.items()])

            # JWT tokens dhundo response body aur headers mein
            found_tokens = set()
            for text in [body, all_headers_text]:
                matches = JWT_PATTERN.findall(text)
                found_tokens.update(matches)

            if not found_tokens:
                return {
                    "status": "Safe / Clean",
                    "timestamp": datetime.utcnow().isoformat(),
                    "summary": "No JWT tokens found in response body/headers to analyze."
                }

            all_findings = []
            for token in list(found_tokens)[:5]:  # Max 5 tokens analyze karo
                findings = _analyze_jwt(token)
                all_findings.extend(findings)

            if all_findings:
                # Duplicates hatao
                seen = set()
                unique_findings = []
                for f in all_findings:
                    if f["issue"] not in seen:
                        seen.add(f["issue"])
                        unique_findings.append(f)

                max_cvss = max(f["cvss"] for f in unique_findings)
                details = [f"[{f['severity']}] {f['issue']} — {f['detail']}" for f in unique_findings]

                return {
                    "status": "Vulnerable / Alert" if max_cvss >= 7.0 else "Completed",
                    "timestamp": datetime.utcnow().isoformat(),
                    "summary": (
                        f"🎫 JWT analyzed ({len(found_tokens)} token(s) found) — Max CVSS: {max_cvss}\n" +
                        "\n".join(details)
                    )
                }

            return {
                "status": "Safe / Clean",
                "timestamp": datetime.utcnow().isoformat(),
                "summary": f"Found {len(found_tokens)} JWT token(s) — no security issues detected."
            }

    except Exception as e:
        return {
            "status": "Error",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"JWT analyzer error: {str(e)}"
        }


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
        print(f"\n[*] JWT analyzing: {target}\n")
        async with aiohttp.ClientSession() as session:
            result = await run(target, session)
            print(f"Status  : {result['status']}")
            print(f"Summary : {result['summary']}")

    asyncio.run(_test())
