"""
PathTravScan — Vulnerability Detector
Scores HTTP responses for path traversal success using signatures + heuristics.
"""
import re
from typing import Dict, List

# ── Per-file detection signatures ─────────────────────────────────────────────
SIGNATURES: Dict[str, List[str]] = {
    "/etc/passwd":       ["root:x:0:", "daemon:x:", "nobody:x:", "/bin/bash", "/sbin/nologin"],
    "/etc/shadow":       ["root:$", ":18", "daemon:*:", "nobody:!:"],
    "/etc/hosts":        ["127.0.0.1", "localhost", "::1"],
    "/etc/hostname":     [],
    "/proc/version":     ["Linux version", "gcc version", "GNU"],
    "/proc/self/environ":["HOME=", "PATH=", "SHELL="],
    "win.ini":           ["[fonts]", "[extensions]", "for 16-bit"],
    "web.config":        ["<configuration>", "connectionStrings", "appSettings"],
    ".env":              ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "DATABASE_URL="],
    "id_rsa":            ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
    "wp-config.php":     ["DB_NAME", "DB_PASSWORD", "table_prefix"],
    "config.php":        ["define(", "DB_HOST", "password"],
    "my.cnf":            ["[mysqld]", "datadir", "socket"],
    "nginx.conf":        ["server_name", "listen", "root /", "proxy_pass"],
    "apache2.conf":      ["ServerRoot", "DocumentRoot", "<VirtualHost"],
    "auth.log":          ["sshd", "Failed password", "Accepted publickey"],
    "access.log":        ["GET /", "POST /", "HTTP/1."],
    "default":           ["root:x:", "daemon:", "/bin/bash", "BEGIN RSA",
                          "APP_KEY=", "[fonts]", "DB_PASSWORD", "Linux version"],
}

_FALSE_POS = re.compile(
    r"(404 not found|page not found|file not found|access denied"
    r"|forbidden|error occurred|object not found|no such file)",
    re.I,
)

SEVERITY_MAP = {range(80, 101): "CRITICAL", range(60, 80): "HIGH",
                range(40, 60): "MEDIUM",    range(0,  40): "INFO"}


class VulnDetector:
    """Analyse a response dict and return confidence score + evidence."""

    def analyse(self, response: Dict, target_file: str) -> Dict:
        empty = dict(vulnerable=False, confidence=0, evidence=[], body_preview="")
        if response.get("error") or not response.get("body"):
            return empty

        body   = response["body"]
        status = response.get("status_code") or 0
        length = response.get("length", 0)

        if not body or status in (400, 403, 404, 405, 500, 503):
            return empty

        sigs     = self._sigs(target_file)
        evidence = [s for s in sigs if s.lower() in body.lower()]

        if not evidence:
            # hostname: any short 200 body
            if "hostname" in target_file and status == 200 and 0 < length < 64:
                evidence = [f"Short 200 body ({length}B)"]
            else:
                return empty

        conf = min(90, len(evidence) * 30)
        if status == 200:   conf = min(100, conf + 15)
        if length > 200:    conf = min(100, conf + 5)
        if _FALSE_POS.search(body[:600]) and len(evidence) == 1:
            conf = max(0, conf - 45)
        if length < 50 and "hostname" not in target_file:
            conf = max(0, conf - 20)

        return dict(vulnerable=conf >= 40, confidence=conf,
                    evidence=evidence, body_preview=body[:400])

    def severity(self, result: Dict) -> str:
        c = result.get("confidence", 0)
        for r, label in SEVERITY_MAP.items():
            if c in r:
                return label
        return "INFO"

    def _sigs(self, target_file: str) -> List[str]:
        for key, sigs in SIGNATURES.items():
            if key in target_file:
                return sigs
        return SIGNATURES["default"]
