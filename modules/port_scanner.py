#!/usr/bin/env python3
"""
Valkyrie 20-in-1 Framework - Async Port Scanner Module
Author: Sonia
Description: High-speed asynchronous TCP port scanner for discovering open services.
"""

import asyncio
import logging
from datetime import datetime

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # ASCII: Sonia

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP Submission", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    2049: "NFS", 2375: "Docker", 2376: "Docker TLS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM HTTP",
    5986: "WinRM HTTPS", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    9090: "WebSocket", 27017: "MongoDB"
}

DANGEROUS_PORTS = {23, 3389, 6379, 27017, 2375, 5900, 161}


async def scan_port(target_ip: str, port: int, timeout: float = 1.5) -> dict:
    """Ek single port ko async scan karta hai, banner bhi grab karta hai."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port), timeout=timeout
        )

        banner = ""
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            banner = data.decode('utf-8', errors='ignore').strip()[:100]
        except Exception:
            pass

        writer.close()
        await writer.wait_closed()

        service = COMMON_PORTS.get(port, "Unknown")
        risk = "HIGH" if port in DANGEROUS_PORTS else "Normal"

        return {"port": port, "state": "open", "service": service, "banner": banner, "risk": risk}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"port": port, "state": "closed", "service": ""}
    except Exception as e:
        return {"port": port, "state": "error", "service": str(e)}


async def run(target_url: str, session=None) -> dict:
    """
    Valkyrie Module: Multi-threaded async port scanner.
    Hostname resolve karta hai aur common ports ko scan karta hai.
    """
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        return {"status": "Tampered", "summary": "Module integrity violation detected."}

    clean_host = target_url.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0]

    try:
        target_ip = (await asyncio.get_event_loop().getaddrinfo(clean_host, 80))[0][4][0]
    except Exception as e:
        return {
            "status": "Error",
            "summary": f"DNS resolution failed for {clean_host}: {str(e)}"
        }

    all_ports = list(COMMON_PORTS.keys())
    tasks = [scan_port(target_ip, port) for port in all_ports]
    results = await asyncio.gather(*tasks)

    open_ports = [r for r in results if r["state"] == "open"]
    closed_count = len([r for r in results if r["state"] == "closed"])
    high_risk = [r for r in open_ports if r.get("risk") == "HIGH"]

    summary = f"Scanned {len(all_ports)} common ports on {target_ip} — {len(open_ports)} open, {closed_count} closed."
    if high_risk:
        risky_list = ", ".join([f"{r['port']}({r['service']})" for r in high_risk])
        summary += f" ⚠️ HIGH RISK PORTS OPEN: {risky_list}"

    return {
        "status": "Completed",
        "timestamp": datetime.utcnow().isoformat(),
        "summary": summary,
        "open_ports": open_ports,
        "target_ip": target_ip
    }


if __name__ == "__main__":
    import sys

    async def _test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
        print(f"\n[*] Port scanning: {target}\n")
        result = await run(target)
        print(f"Status  : {result['status']}")
        print(f"Summary : {result['summary']}")

    asyncio.run(_test())
