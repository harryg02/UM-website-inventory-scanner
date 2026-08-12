"""Pull links, text and email addresses out of HTML using only the stdlib."""

from __future__ import annotations

import re
from html import unescape
from html.parser import HTMLParser

SKIP_TEXT_TAGS = {"script", "style", "noscript", "template", "svg"}

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+"
)

# "first dot last at umich dot edu" style obfuscation, lightly de-obfuscated.
_OBFUSCATION = [
    (re.compile(r"\s*[\[\(\{]\s*at\s*[\]\)\}]\s*", re.I), "@"),
    (re.compile(r"\s*[\[\(\{]\s*dot\s*[\]\)\}]\s*", re.I), "."),
    (re.compile(r"\s+at\s+(?=[A-Za-z0-9\-]+\s+dot\s+)", re.I), "@"),
    (re.compile(r"\s+dot\s+(?=[A-Za-z]{2,10}\b)", re.I), "."),
]

# Things that match the email shape but are not addresses.
_BAD_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net", "domain.com", "email.com",
    "yourdomain.com", "site.com", "sentry.io", "wixpress.com", "2x.png",
}
_BAD_LOCAL_PARTS = {"user", "username", "youremail", "name", "email", "someone", "test"}
_ASSET_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js",
    ".woff", ".woff2", ".ttf", ".ico", ".bmp", ".mp4", ".pdf",
)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.mailtos: list[str] = []
        self.base_href: str | None = None
        self.title: str = ""
        self.meta_refresh: str | None = None
        self._text: list[str] = []
        self._skip_depth = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}

        if tag in SKIP_TEXT_TAGS:
            self._skip_depth += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "base" and a.get("href") and self.base_href is None:
            self.base_href = a["href"].strip()
        elif tag in ("a", "area"):
            href = a.get("href", "").strip()
            if href.lower().startswith("mailto:"):
                self.mailtos.append(href[7:].split("?")[0].strip())
            elif href:
                self.links.append(href)
        elif tag == "meta":
            if a.get("http-equiv", "").lower() == "refresh":
                content = a.get("content", "")
                m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content, re.I)
                if m:
                    self.meta_refresh = m.group(1).strip()

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag in SKIP_TEXT_TAGS and self._skip_depth:
            self._skip_depth -= 1

    def handle_endtag(self, tag):
        if tag in SKIP_TEXT_TAGS and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._in_title:
            self.title += data.strip()
        self._text.append(data)

    @property
    def text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self._text))


class Page:
    """Parsed view of one HTML document."""

    def __init__(self, html: str):
        parser = _PageParser()
        try:
            parser.feed(html)
            parser.close()
        except Exception:
            pass  # malformed markup: keep whatever we got
        self.links = parser.links
        self.mailtos = parser.mailtos
        self.base_href = parser.base_href
        self.title = parser.title
        self.meta_refresh = parser.meta_refresh
        self.text = parser.text
        self._html = html

    def emails(self) -> list[str]:
        """mailto: addresses first, then anything scraped from visible text."""
        found: list[str] = []
        seen: set[str] = set()

        for raw in self.mailtos:
            addr = clean_email(unescape(raw))
            if addr and addr not in seen:
                seen.add(addr)
                found.append(addr)

        body = self.text
        for pattern, repl in _OBFUSCATION:
            body = pattern.sub(repl, body)

        for match in EMAIL_RE.findall(body):
            addr = clean_email(match)
            if addr and addr not in seen:
                seen.add(addr)
                found.append(addr)

        return found


def clean_email(raw: str) -> str:
    """Normalise and reject anything that only looks like an address."""
    if not raw:
        return ""
    addr = unescape(raw).strip().strip(".,;:<>()[]\"'").lower()
    if addr.count("@") != 1:
        return ""

    local, _, domain = addr.partition("@")
    if not local or not domain or "." not in domain:
        return ""
    if ".." in addr or domain.startswith("-") or domain.endswith("-"):
        return ""
    if len(addr) > 254:
        return ""
    if domain in _BAD_EMAIL_DOMAINS or local in _BAD_LOCAL_PARTS:
        return ""
    if any(domain.endswith(s) for s in _ASSET_SUFFIXES):
        return ""
    if re.fullmatch(r"[0-9a-f]{16,}", local):     # tracking / hash noise
        return ""
    tld = domain.rsplit(".", 1)[-1]
    if not tld.isalpha() or len(tld) < 2:
        return ""
    return addr
