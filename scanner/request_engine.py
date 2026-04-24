"""
PathTravScan — Request Engine
Handles HTTP/HTTPS with legacy TLS bypass, proxy support, custom headers.
"""
import ssl
import time
import requests
import urllib3
from typing import Dict, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent":      ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/88.0.4298.103 Safari/537.36"),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection":      "keep-alive",
}


class _LegacyTLSAdapter(requests.adapters.HTTPAdapter):
    """Allows TLS 1.0/1.1 for old backend servers (like SiteScope)."""
    def init_poolmanager(self, *args, **kwargs):
        try:
            from urllib3.util.ssl_ import create_urllib3_context
            ctx = create_urllib3_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except AttributeError:
                ctx.options &= ~getattr(ssl, "OP_NO_TLSv1",   0)
                ctx.options &= ~getattr(ssl, "OP_NO_TLSv1_1", 0)
            kwargs["ssl_context"] = ctx
        except Exception:
            pass
        super().init_poolmanager(*args, **kwargs)


class RequestEngine:
    """
    Sends HTTP requests and returns a normalised result dict.

    Parameters
    ----------
    timeout      : request timeout in seconds
    legacy_tls   : enable TLS 1.0 for old servers
    proxy        : proxy URL e.g. 'http://127.0.0.1:8080' (Burp Suite)
    extra_headers: merged into every request
    """

    def __init__(
        self,
        timeout: int = 10,
        legacy_tls: bool = True,
        proxy: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.timeout       = timeout
        self.proxies       = {"http": proxy, "https": proxy} if proxy else None
        self.extra_headers = extra_headers or {}
        self.session       = self._build_session(legacy_tls)

    def _build_session(self, legacy_tls: bool) -> requests.Session:
        s = requests.Session()
        if legacy_tls:
            s.mount("https://", _LegacyTLSAdapter())
        return s

    def send(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Dict:
        """Send one request. Always returns a dict — never raises."""
        merged = {**DEFAULT_HEADERS, **self.extra_headers, **(headers or {})}
        t0 = time.time()
        result = dict(url=url, method=method, request_headers=merged,
                      status_code=None, response_headers={},
                      body="", length=0, time_ms=0, error=None)
        try:
            r = self.session.request(
                method=method, url=url, headers=merged,
                data=body, cookies=cookies,
                timeout=self.timeout, verify=False,
                proxies=self.proxies, allow_redirects=True,
            )
            result["status_code"]      = r.status_code
            result["response_headers"] = dict(r.headers)
            result["body"]             = r.text
            result["length"]           = len(r.content)
        except requests.exceptions.SSLError as e:
            result["error"] = f"SSL Error (try --legacy-tls): {str(e)[:120]}"
        except requests.exceptions.ProxyError as e:
            result["error"] = f"Proxy Error: {str(e)[:120]}"
        except requests.exceptions.ConnectionError as e:
            result["error"] = f"Connection Error: {str(e)[:120]}"
        except requests.exceptions.Timeout:
            result["error"] = "Timeout"
        except Exception as e:
            result["error"] = f"Error: {str(e)[:120]}"
        result["time_ms"] = round((time.time() - t0) * 1000, 1)
        return result
