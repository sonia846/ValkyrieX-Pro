#!/usr/bin/env python3
"""
Valkyrie Module: SSL/TLS Security Auditor
Author: Sonia
Description: SSL/TLS certificate aur configuration ka audit karta hai,
             expired certs, weak protocols, aur missing HTTPS detect karta hai.
"""

import ssl
import socket
import asyncio
from datetime import datetime, timezone

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


def _sync_ssl_check(hostname: str, port: int = 443) -> dict:
    """Synchronous SSL check — executor mein run hoga."""
    findings = []

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                protocol = ssock.version()
                cipher = ssock.cipher()

                # Weak protocol check
                if protocol in WEAK_PROTOCOLS:
                    findings.append({
                        "severity": "High",
                        "cvss": 7.0,
                        "issue": f"Weak TLS protocol in use: {protocol}",
                        "detail": "Outdated protocol vulnerable to known attacks (POODLE, BEAST, etc)."
                    })

                # Weak cipher check
                if cipher and ("RC4" in cipher[0] or "DES" in cipher[0] or "MD5" in cipher[0]):
                    findings.append({
                        "severity": "High",
                        "cvss": 6.5,
                        "issue": f"Weak cipher suite: {cipher[0]}",
                        "detail": "Cipher is cryptographically broken or weak."
                    })

                # Real cert check needs proper verification — use separate context
                try:
                    verify_context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=8) as vsock:
                        with verify_context.wrap_socket(vsock, server_hostname=hostname) as vssock:
                            real_cert = vssock.getpeercert()

                            # Expiry check
                            expiry_str = real_cert.get('notAfter', '')
                            if expiry_str:
                                expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                                days_left = (expiry_date - datetime.now(timezone.utc)).days

                                if days_left < 0:
                                    findings.append({
                                        "severity": "Critical",
                                        "cvss": 9.0,
                                        "issue": "SSL Certificate EXPIRED",
                                        "detail": f"Certificate expired {abs(days_left)} days ago."
                                    })
                                elif days_left < 14:
                                    findings.append({
                                        "severity": "Medium",
                                        "cvss": 4.5,
                                        "issue": "SSL Certificate expiring soon",
                                        "detail": f"Certificate expires in {days_left} days."
                                    })
                except ssl.SSLCertVerificationError as e:
                    findings.append({
                        "severity": "High",
                        "cvss": 7.5,
                        "issue": "SSL Certificate verification failed",
                        "detail": str(e)[:150]
                    })
                except Exception:
                    pass

        return {"success": True, "findings": findings, "protocol": protocol}

    except socket.timeout:
        return {"success": False, "error": "Connection timed out"}
    except ConnectionRefusedError:
        return {"success": False, "error": "HTTPS port 443 not open — site may be HTTP only"}
    except ssl.SSLError as e:
        return {"success": False, "error": f"SSL Error: {str(e)[:150]}"}
    except Exception as e:
        return {"success": False, "error": f"Connection error: {str(e)[:150]}"}


async def run(target_url: str, session=None) -> dict:
    """
    Valkyrie Module: SSL/TLS auditor.
    """
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        return {"status": "Tampered", "summary": "Module integrity violation detected."}

    clean_host = target_url.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0]

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _sync_ssl_check, clean_host)

    if not result["success"]:
        return {
            "status": "Warning",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": f"SSL check incomplete: {result['error']}"
        }

    findings = result["findings"]

    if findings:
        max_cvss = max(f["cvss"] for f in findings)
        details = [f"[{f['severity']}] {f['issue']} — {f['detail']}" for f in findings]

        return {
            "status": "Vulnerable / Alert" if max_cvss >= 7.0 else "Completed",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": (
                f"🔒 SSL/TLS issues found ({result['protocol']}) — Max CVSS: {max_cvss}\n" +
                "\n".join(details)
            )
        }

    return {
        "status": "Safe / Clean",
        "timestamp": datetime.utcnow().isoformat(),
        "summary": f"SSL/TLS configuration looks secure. Protocol: {result['protocol']}"
    }


# Backward compatibility — sync wrapper
def audit_ssl(url: str) -> str:
    clean_host = url.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0]
    result = _sync_ssl_check(clean_host)
    if not result["success"]:
        return f"SSL check incomplete: {result['error']}"
    if result["findings"]:
        return f"{len(result['findings'])} SSL issue(s) found."
    return "SSL configuration looks secure."


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "https://google.com"
        print(f"\n[*] SSL auditing: {target}\n")
        result = await run(target)
        print(f"Status  : {result['status']}")
        print(f"Summary : {result['summary']}")

    asyncio.run(_test())
