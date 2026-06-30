#!/usr/bin/env python3
"""
ValkyrieX Pro — AI Vulnerability Analyzer
Author: Sonia
Description: Gemini AI se scan results analyze karta hai, 
             false positives hata ke severity assign karta hai.
"""

import json
import os
from datetime import datetime

AUTHOR_SIGNATURE = b"\x53\x6F\x6E\x69\x61"  # Sonia

def _verify_author():
    if AUTHOR_SIGNATURE.decode('utf-8') != "Sonia":
        raise PermissionError("ValkyrieX: Unauthorized execution blocked.")

def analyze_with_ai(scan_results: dict, api_key: str) -> dict:
    """Gemini AI se vulnerabilities analyze karo."""
    _verify_author()
    
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro')

        prompt = f"""
You are a senior bug bounty hunter and security researcher.
Analyze these vulnerability scan results and provide:

1. VERIFIED findings (remove false positives)
2. CVSS Score (0.0 - 10.0) for each finding
3. Severity: P1(Critical) / P2(High) / P3(Medium) / P4(Low)
4. Exploitation steps (1-3 steps)
5. Remediation recommendation
6. HackerOne report title suggestion

Scan Results:
{json.dumps(scan_results, indent=2)}

Respond in JSON format:
{{
  "verified_findings": [
    {{
      "title": "...",
      "severity": "P1/P2/P3/P4",
      "cvss_score": 0.0,
      "description": "...",
      "exploitation": "...",
      "remediation": "...",
      "hackerone_title": "..."
    }}
  ],
  "executive_summary": "...",
  "total_critical": 0,
  "total_high": 0,
  "total_medium": 0,
  "total_low": 0,
  "estimated_bounty_range": "$X - $Y"
}}
"""
        response = model.generate_content(prompt)
        
        try:
            text = response.text.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()
            ai_analysis = json.loads(text)
        except json.JSONDecodeError:
            ai_analysis = {
                "verified_findings": [],
                "executive_summary": response.text,
                "ai_raw_response": response.text
            }

        return {
            "status": "AI Analysis Complete",
            "timestamp": datetime.utcnow().isoformat(),
            "author": "Sonia",
            "ai_analysis": ai_analysis
        }

    except ImportError:
        return _fallback_analysis(scan_results)
    except Exception as e:
        return {
            "status": "AI Error",
            "error": str(e),
            "fallback": _fallback_analysis(scan_results)
        }


def _fallback_analysis(scan_results: dict) -> dict:
    """AI na ho to manual severity assign karo."""
    _verify_author()
    
    severity_map = {
        "sqli_scanner": ("P1", 9.0, "Critical"),
        "xss_scanner": ("P2", 7.5, "High"),
        "secret_hunter": ("P2", 8.0, "High"),
        "subdomain_takeover": ("P2", 8.0, "High"),
        "jwt_analyzer": ("P2", 7.0, "High"),
        "cors_auditor": ("P3", 5.0, "Medium"),
        "open_redirect": ("P3", 5.0, "Medium"),
        "crlf_tester": ("P3", 5.5, "Medium"),
        "dir_bruteforcer": ("P3", 4.0, "Medium"),
        "header_auditor": ("P4", 3.0, "Low"),
        "ssl_auditor": ("P4", 3.5, "Low"),
        "waf_detector": ("P4", 2.0, "Info"),
    }

    findings = []
    for module_output in scan_results.get("module_outputs", []):
        module = module_output.get("module", "")
        status = module_output.get("status", "")
        
        if "Vulnerable" in status or "Alert" in status:
            sev_info = severity_map.get(module, ("P4", 2.0, "Low"))
            findings.append({
                "module": module,
                "severity": sev_info[0],
                "cvss_score": sev_info[1],
                "severity_label": sev_info[2],
                "summary": module_output.get("summary", ""),
                "timestamp": module_output.get("timestamp", "")
            })

    return {
        "status": "Fallback Analysis (No AI)",
        "timestamp": datetime.utcnow().isoformat(),
        "findings": findings,
        "total_vulnerabilities": len(findings)
    }
