"""
PathTravScan — Reporter
Saves scan output as JSON and plain-text reports.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List


class Reporter:

    def save_json(self, results: List[Dict], target_url: str,
                  target_file: str, out: str) -> str:
        findings = [r for r in results if r.get("vulnerable")]
        report = {
            "tool": "PathTravScan", "version": "1.0.0",
            "timestamp": datetime.now().isoformat(),
            "target_url": target_url, "target_file": target_file,
            "summary": {
                "total_payloads":  len(results),
                "vulnerabilities": len(findings),
                "critical": sum(1 for r in findings if r.get("severity") == "CRITICAL"),
                "high":     sum(1 for r in findings if r.get("severity") == "HIGH"),
                "medium":   sum(1 for r in findings if r.get("severity") == "MEDIUM"),
            },
            "findings": [{k: v for k, v in r.items() if k != "body"} for r in findings],
            "all_results": [
                {k: r[k] for k in ("index","payload","type","status","length",
                                   "time_ms","error","vulnerable","confidence")}
                for r in results
            ],
        }
        p = Path(out); p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(report, indent=2))
        return str(p)

    def save_txt(self, results: List[Dict], target_url: str,
                 target_file: str, out: str) -> str:
        findings = [r for r in results if r.get("vulnerable")]
        sep = "=" * 70
        lines = [
            sep, "  PathTravScan — Scan Report", sep,
            f"  Timestamp : {datetime.now():%Y-%m-%d %H:%M:%S}",
            f"  Target    : {target_url}",
            f"  File      : {target_file}",
            f"  Payloads  : {len(results)}",
            f"  Findings  : {len(findings)}", sep, "",
        ]
        if not findings:
            lines.append("  No vulnerabilities detected.\n")
        else:
            for i, r in enumerate(findings, 1):
                lines += [
                    f"  [{i}] {r.get('severity','?')} — Confidence {r.get('confidence',0)}%",
                    f"      Payload  : {r['payload']}",
                    f"      Type     : {r['type']}  Encoding: {r['encoding']}",
                    f"      Status   : {r['status']}  Length: {r['length']}B  Time: {r['time_ms']}ms",
                    f"      Evidence : {', '.join(r.get('evidence', []))}",
                    f"      URL      : {r['url']}", "",
                ]
        lines += [sep, "  END OF REPORT", sep]
        p = Path(out); p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(lines) + "\n")
        return str(p)
