"""
PathTravScan — Scan Engine
Orchestrates payload dispatch with optional threading.
"""
import time
import threading
from typing import Callable, Dict, List, Optional

from scanner.request_engine import RequestEngine
from scanner.vuln_detector  import VulnDetector


class ScanEngine:
    """
    Iterates payloads, dispatches requests, collects results.

    Parameters
    ----------
    req           : RequestEngine
    det           : VulnDetector
    threads       : concurrent threads (1 = sequential)
    delay         : seconds between requests per thread
    stop_on_first : stop after first confirmed finding
    """

    def __init__(self, req: RequestEngine, det: VulnDetector,
                 threads: int = 1, delay: float = 0.0,
                 stop_on_first: bool = False):
        self.req           = req
        self.det           = det
        self.threads       = max(1, threads)
        self.delay         = delay
        self.stop_on_first = stop_on_first
        self._results: List[Dict] = []
        self._findings: List[Dict] = []
        self._lock  = threading.Lock()
        self._stop  = threading.Event()

    # ── public ────────────────────────────────────────────────────────
    def run(self, base_url: str, payloads: List[Dict], target_file: str,
            on_result: Optional[Callable[[Dict], None]] = None) -> List[Dict]:
        self._results = []; self._findings = []; self._stop.clear()
        base_url = base_url.rstrip("/")
        if self.threads == 1:
            self._sequential(base_url, payloads, target_file, on_result)
        else:
            self._threaded(base_url, payloads, target_file, on_result)
        return self._findings

    def abort(self):
        self._stop.set()

    @property
    def results(self) -> List[Dict]:
        return self._results

    @property
    def findings(self) -> List[Dict]:
        return self._findings

    # ── private ───────────────────────────────────────────────────────
    def _process(self, index: int, p: Dict, base_url: str,
                 target_file: str, on_result: Optional[Callable]) -> None:
        if self._stop.is_set():
            return
        url      = base_url + p["payload"]
        resp     = self.req.send(url)
        analysis = self.det.analyse(resp, target_file)
        result = dict(
            index=index, payload=p["payload"], type=p.get("type","?"),
            encoding=p.get("encoding","-"), depth=p.get("depth",0),
            url=url, status=resp.get("status_code"), length=resp.get("length",0),
            time_ms=resp.get("time_ms",0), error=resp.get("error"),
            body=resp.get("body",""), response_headers=resp.get("response_headers",{}),
            vulnerable=analysis["vulnerable"], confidence=analysis["confidence"],
            evidence=analysis["evidence"], body_preview=analysis.get("body_preview",""),
            severity=self.det.severity(analysis),
        )
        with self._lock:
            self._results.append(result)
            if analysis["vulnerable"]:
                self._findings.append(result)
                if self.stop_on_first:
                    self._stop.set()
        if on_result:
            on_result(result)

    def _sequential(self, base_url, payloads, tf, cb):
        for i, p in enumerate(payloads):
            if self._stop.is_set():
                break
            self._process(i + 1, p, base_url, tf, cb)
            if self.delay:
                time.sleep(self.delay)

    def _threaded(self, base_url, payloads, tf, cb):
        sem = threading.Semaphore(self.threads)
        def worker(i, p):
            with sem:
                self._process(i, p, base_url, tf, cb)
                if self.delay:
                    time.sleep(self.delay)
        ts = []
        for i, p in enumerate(payloads):
            if self._stop.is_set():
                break
            t = threading.Thread(target=worker, args=(i+1, p), daemon=True)
            ts.append(t); t.start()
        for t in ts:
            t.join()
