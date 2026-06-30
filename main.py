#!/usr/bin/env python3
"""
ValkyrieX Pro — AI-Powered Bug Bounty Hunter
Author: Sonia 🇵🇰
Version: 1.0.0
Description: Master orchestrator — 13 modules + AI analysis + auto reports
"""

import asyncio
import aiohttp
import sys
import os
import json
import argparse
import logging
from datetime import datetime

# ─── Integrity Protection ───────────────────────────────────────────
AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # Sonia
TOOL_NAME = "ValkyrieX Pro"
VERSION = "1.0.0"

def _verify_author():
    """Sirf Sonia ka tool run hoga."""
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        print("\n[!] UNAUTHORIZED: This tool is locked to its original author.")
        print("[!] Execution blocked. ValkyrieX Pro by Sonia only.")
        sys.exit(1)

_verify_author()

# ─── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("valkyriex.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# ─── Banner ─────────────────────────────────────────────────────────
BANNER = """
\033[95m
██╗   ██╗ █████╗ ██╗     ██╗  ██╗██╗   ██╗██████╗ ██╗███████╗    ██╗  ██╗
██║   ██║██╔══██╗██║     ██║ ██╔╝╚██╗ ██╔╝██╔══██╗██║██╔════╝    ╚██╗██╔╝
██║   ██║███████║██║     █████╔╝  ╚████╔╝ ██████╔╝██║█████╗       ╚███╔╝ 
╚██╗ ██╔╝██╔══██║██║     ██╔═██╗   ╚██╔╝  ██╔══██╗██║██╔══╝       ██╔██╗ 
 ╚████╔╝ ██║  ██║███████╗██║  ██╗   ██║   ██║  ██║██║███████╗    ██╔╝ ██╗
  ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝    ╚═╝  ╚═╝
\033[0m
\033[96m              ██████╗ ██████╗  ██████╗ \033[0m
\033[96m              ██╔══██╗██╔══██╗██╔═══██╗\033[0m
\033[96m              ██████╔╝██████╔╝██║   ██║\033[0m
\033[96m              ██╔═══╝ ██╔══██╗██║   ██║\033[0m
\033[96m              ██║     ██║  ██║╚██████╔╝\033[0m
\033[96m              ╚═╝     ╚═╝  ╚═╝ ╚═════╝ \033[0m

\033[93m         🛡️  AI-Powered Bug Bounty Hunter v1.0.0\033[0m
\033[95m         👩‍💻 Author: Sonia 🇵🇰  |  ValkyrieX Pro\033[0m
\033[90m         ⚠️  Authorized Use Only — Locked to Author\033[0m
"""

# ─── All Modules ─────────────────────────────────────────────────────
ALL_MODULES = [
    "xss_scanner",
    "sqli_scanner", 
    "port_scanner",
    "dir_bruteforcer",
    "header_auditor",
    "cors_auditor",
    "ssl_auditor",
    "open_redirect",
    "crlf_tester",
    "jwt_analyzer",
    "secret_hunter",
    "subdomain_takeover",
    "waf_detector",
]

class ValkyrieXEngine:
    def __init__(self, target: str, config: dict):
        _verify_author()
        self.target = target
        self.config = config
        self.semaphore = asyncio.Semaphore(
            config.get("scan_settings", {}).get("concurrency_limit", 25)
        )
        self.results = {
            "target": target,
            "scan_time": datetime.utcnow().isoformat(),
            "tool": TOOL_NAME,
            "version": VERSION,
            "author": "Sonia",
            "module_outputs": []
        }

    async def run_module(self, module_name: str, session: aiohttp.ClientSession):
        """Ek module safely execute karo."""
        async with self.semaphore:
            try:
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))
                mod = __import__(module_name)
                
                if hasattr(mod, 'run'):
                    output = mod.run(self.target, session)
                    if asyncio.iscoroutine(output):
                        output = await output
                elif hasattr(mod, 'scan_vulnerabilities'):
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None, lambda: mod.scan_vulnerabilities(self.target)
                    )
                    output = {"status": "Completed", "summary": str(result),
                              "timestamp": datetime.utcnow().isoformat()}
                else:
                    output = {"status": "Warning", "summary": "No run() found.",
                              "timestamp": datetime.utcnow().isoformat()}

                if isinstance(output, dict):
                    self.results["module_outputs"].append({
                        "module": module_name,
                        "status": output.get("status", "Executed"),
                        "timestamp": output.get("timestamp", datetime.utcnow().isoformat()),
                        "summary": output.get("summary", "Completed.")
                    })
                    
            except ImportError:
                self.results["module_outputs"].append({
                    "module": module_name,
                    "status": "Missing",
                    "timestamp": datetime.utcnow().isoformat(),
                    "summary": f"Module file not found: modules/{module_name}.py"
                })
            except Exception as e:
                self.results["module_outputs"].append({
                    "module": module_name,
                    "status": "Error",
                    "timestamp": datetime.utcnow().isoformat(),
                    "summary": f"Error: {str(e)}"
                })

    async def run_all(self, modules: list, session: aiohttp.ClientSession):
        tasks = [self.run_module(m, session) for m in modules]
        await asyncio.gather(*tasks)


def load_config() -> dict:
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def print_live_summary(results: dict):
    """Scan ke baad quick summary print karo."""
    outputs = results.get("module_outputs", [])
    vulns = [m for m in outputs if "Vulnerable" in m.get("status","") or "Alert" in m.get("status","")]
    safe = [m for m in outputs if m.get("status") == "Safe / Clean"]
    errors = [m for m in outputs if m.get("status") in ("Error", "Missing", "Crashed")]
    
    print("\n" + "=" * 65)
    print(f"  📊 SCAN SUMMARY — ValkyrieX Pro by Sonia")
    print("=" * 65)
    print(f"  🎯 Target    : {results['target']}")
    print(f"  ⏰ Scan Time : {results['scan_time']} UTC")
    print(f"  🔍 Modules   : {len(outputs)} executed")
    print(f"  🔴 Vulns     : {len(vulns)} found")
    print(f"  🟢 Clean     : {len(safe)} passed")
    print(f"  ⚠️  Errors    : {len(errors)}")
    
    if vulns:
        print("\n  🚨 VULNERABILITIES DETECTED:")
        for v in vulns:
            print(f"     • [{v['module']}] {v['status']}")
            print(f"       {v['summary'][:80]}...")
    print("=" * 65)


async def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="ValkyrieX Pro — AI Bug Bounty Hunter by Sonia"
    )
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--ai", action="store_true", help="Enable AI analysis")
    parser.add_argument("--module", help="Run specific module only")
    parser.add_argument("--report", default="all", 
                        choices=["all", "html", "txt", "json", "docx"],
                        help="Report format")
    
    args = parser.parse_args()
    
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    config = load_config()
    
    print(f"\n\033[92m[*] Target    : {target}\033[0m")
    print(f"\033[92m[*] Time      : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\033[0m")
    print(f"\033[92m[*] AI Mode   : {'ON' if args.ai else 'OFF'}\033[0m")
    print(f"\033[92m[*] Reports   : {args.report.upper()}\033[0m\n")
    
    modules_to_run = [args.module] if args.module else ALL_MODULES
    
    engine = ValkyrieXEngine(target=target, config=config)
    
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        print(f"\033[94m[*] Launching {len(modules_to_run)} modules...\033[0m\n")
        await engine.run_all(modules_to_run, session)
    
    print_live_summary(engine.results)
    
    # AI Analysis
    ai_result = {}
    if args.ai:
        print("\n\033[94m[*] Running AI Analysis...\033[0m")
        try:
            from ai_engine.analyzer import analyze_with_ai
            api_key = config.get("gemini_api_key", "")
            if api_key and api_key != "YOUR_GEMINI_API_KEY_HERE":
                ai_result = analyze_with_ai(engine.results, api_key)
                print("\033[92m[+] AI Analysis complete!\033[0m")
            else:
                print("\033[93m[!] No Gemini API key found. Add it to config.json\033[0m")
                from ai_engine.analyzer import _fallback_analysis
                ai_result = {"fallback": _fallback_analysis(engine.results)}
        except Exception as e:
            print(f"\033[91m[-] AI Error: {e}\033[0m")
    
    # Generate Reports
    print(f"\n\033[94m[*] Generating reports...\033[0m")
    try:
        from ai_engine.report_writer import generate_all_reports
        generated = generate_all_reports(engine.results, ai_result, target, "reports")
        print(f"\033[92m[+] Reports saved:\033[0m")
        for g in generated:
            print(f"    📄 {g}")
    except Exception as e:
        print(f"\033[91m[-] Report error: {e}\033[0m")
    
    print(f"\n\033[95m{'=' * 65}\033[0m")
    print(f"\033[95m  ✅ ValkyrieX Pro scan complete — by Sonia 🇵🇰\033[0m")
    print(f"\033[95m{'=' * 65}\033[0m\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\033[91m[-] Scan interrupted by user.\033[0m")
        sys.exit(0)
    except Exception as e:
        logging.critical(f"Fatal error: {e}")
        sys.exit(1)
