"""HTTP layer: one polite, guarded GET used by both the crawler and profiler."""

from __future__ import annotations

import codecs
import re
import threading
import time
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter

from .config import USER_AGENT
from .urls import host_of

OK = "ok"
CHALLENGED = "challenged"      # bot-protection interstitial, not real content
HTTP_ERROR = "http_error"
NON_HTML = "non_html"
ERROR = "error"


@dataclass
class Response:
    url: str
    status: str
    http_status: int = 0
    text: str = ""
    final_url: str = ""
    note: str = ""

    @property
    def usable(self) -> bool:
        return self.status == OK and bool(self.text)


class Fetcher:
    """Thread-safe GET with per-host politeness, size caps and retries."""

    def __init__(self, timeout: float = 20.0, per_host_delay: float = 0.4,
                 max_bytes: int = 2_000_000, pool: int = 16):
        self.timeout = timeout
        self.per_host_delay = per_host_delay
        self.max_bytes = max_bytes

        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=pool, pool_maxsize=pool, max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

        self._lock = threading.Lock()
        self._next_ok: dict[str, float] = {}

    def _throttle(self, host: str) -> None:
        """Sleep just long enough that we never hammer a single host."""
        while True:
            with self._lock:
                now = time.monotonic()
                ready = self._next_ok.get(host, 0.0)
                if now >= ready:
                    self._next_ok[host] = now + self.per_host_delay
                    return
                wait = ready - now
            time.sleep(min(wait, 5.0))

    def get(self, url: str, retries: int = 1) -> Response:
        host = host_of(url)
        last_exc = ""

        for attempt in range(retries + 1):
            self._throttle(host)
            try:
                with self.session.get(
                    url, timeout=self.timeout, allow_redirects=True, stream=True
                ) as r:
                    ctype = r.headers.get("Content-Type", "").lower()
                    challenged = (
                        r.headers.get("Cf-Mitigated", "").lower() == "challenge"
                        or r.status_code in (403, 503)
                    )

                    if r.status_code >= 400 and not challenged:
                        return Response(url, HTTP_ERROR, r.status_code, final_url=r.url,
                                        note=f"HTTP {r.status_code}")

                    if ctype and not any(t in ctype for t in ("html", "xml", "text/plain")):
                        return Response(url, NON_HTML, r.status_code, final_url=r.url,
                                        note=ctype.split(";")[0])

                    body = self._read_capped(r)
                    text = self._decode(r, body)

                    if challenged and looks_like_challenge(text):
                        return Response(url, CHALLENGED, r.status_code, final_url=r.url,
                                        note="bot-protection interstitial")
                    if r.status_code >= 400:
                        return Response(url, HTTP_ERROR, r.status_code, final_url=r.url,
                                        note=f"HTTP {r.status_code}")

                    return Response(url, OK, r.status_code, text=text, final_url=r.url)

            except requests.RequestException as exc:
                last_exc = type(exc).__name__
                if attempt < retries:
                    time.sleep(0.8 * (attempt + 1))

        return Response(url, ERROR, note=last_exc or "request failed")

    def _read_capped(self, r: requests.Response) -> bytes:
        buf = bytearray()
        for chunk in r.iter_content(65536):
            buf += chunk
            if len(buf) >= self.max_bytes:
                break
        return bytes(buf)

    @staticmethod
    def _decode(r: requests.Response, body: bytes) -> str:
        """Decode a streamed body.

        `requests.apparent_encoding` is unavailable here -- it reads
        `r.content`, which raises once the body has been consumed by
        `iter_content`. Sniff the declared charset from the bytes instead.
        """
        enc = r.encoding
        if not enc and body.startswith(codecs.BOM_UTF8):
            enc = "utf-8-sig"
        if not enc:
            match = _CHARSET_RE.search(body[:4096])
            if match:
                enc = match.group(1).decode("ascii", "ignore")
        try:
            return body.decode(enc or "utf-8", errors="replace")
        except (LookupError, TypeError, ValueError):
            return body.decode("utf-8", errors="replace")

    def close(self) -> None:
        self.session.close()


_CHARSET_RE = re.compile(rb"""charset["']?\s*=\s*["']?([A-Za-z0-9_\-]+)""", re.I)

CHALLENGE_MARKERS = (
    "just a moment",
    "cf-browser-verification",
    "challenges.cloudflare.com",
    "__cf_chl",
    "enable javascript and cookies to continue",
    "checking your browser before accessing",
    "attention required! | cloudflare",
    "incapsula incident id",
    "px-captcha",
    "access denied",
)


def looks_like_challenge(text: str) -> bool:
    head = text[:8000].lower()
    return any(m in head for m in CHALLENGE_MARKERS)
