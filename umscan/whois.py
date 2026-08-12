"""A dependency-free WHOIS client speaking the port-43 protocol directly.

There is no `whois` binary to shell out to and no pip to install one, so we
do the referral chase ourselves: IANA tells us the registry server, the
registry often points at a registrar server with the richer record.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from dataclasses import dataclass, field

IANA_SERVER = "whois.iana.org"

# Skip the IANA round-trip for the TLDs a UM crawl actually hits.
KNOWN_TLD_SERVERS = {
    "edu": "whois.educause.edu",
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.publicinterestregistry.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "gov": "whois.dotgov.gov",
    "us": "whois.nic.us",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "tv": "whois.nic.tv",
    "xyz": "whois.nic.xyz",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "health": "whois.nic.health",
    "museum": "whois.nic.museum",
}

REDACTION_MARKERS = (
    "redacted for privacy", "redacted", "data protected", "not disclosed",
    "privacy service", "privacyguardian", "whoisguard", "domains by proxy",
    "contact privacy", "withheld for privacy", "statutory masking",
    "gdpr masked", "identity protection", "on behalf of", "whoisproxy",
    "proxy protection", "privacy protect", "registration private",
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")

_ORG_KEYS = (
    "registrant organization", "registrant organisation", "registrant name",
    "registrant contact organisation", "org", "organization", "organisation",
    "registrant", "owner", "holder", "descr",
)
_EMAIL_KEYS = (
    "registrant email", "registrant contact email", "admin email",
    "administrative contact email", "tech email", "technical contact email",
    "e-mail", "email", "abuse-mailbox",
)
_ABUSE_KEYS = ("registrar abuse contact email",)
_NS_KEYS = ("name server", "nserver", "nameserver", "name servers")

# Block headers used by EDUCAUSE (.edu) and a few ccTLD registries.
_BLOCK_RE = re.compile(
    r"^(registrant|administrative contact|technical contact|name servers)\s*:\s*$",
    re.I | re.M,
)


@dataclass
class WhoisResult:
    domain: str
    ok: bool = False
    server: str = ""
    org: str = ""
    emails: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    registrar: str = ""
    created: str = ""
    redacted: bool = False
    error: str = ""
    raw: str = ""
    real_emails: list[str] = field(default_factory=list)

    def contact(self) -> str:
        """The single cell that goes in the CSV's whois_contact column."""
        if not self.ok:
            return f"lookup failed: {self.error}" if self.error else ""
        bits = []
        if self.org:
            bits.append(self.org)
        if self.real_emails:
            bits.append(self.real_emails[0])
        if bits:
            return " | ".join(bits)
        # Nothing but privacy-proxy boilerplate: say so rather than pass off
        # a registrar abuse mailbox as the domain owner.
        if self.redacted:
            return f"redacted (registrar: {self.registrar})" if self.registrar else "redacted"
        if self.emails:
            return self.emails[0]
        return f"registrar: {self.registrar}" if self.registrar else ""


class WhoisClient:
    """Cached, rate-limited WHOIS lookups keyed by registrable domain."""

    def __init__(self, timeout: float = 15.0, per_server_delay: float = 1.0):
        self.timeout = timeout
        self.per_server_delay = per_server_delay
        self._cache: dict[str, WhoisResult] = {}
        self._cache_lock = threading.Lock()
        self._inflight: dict[str, threading.Lock] = {}
        self._server_lock = threading.Lock()
        self._next_ok: dict[str, float] = {}

    def lookup(self, domain: str) -> WhoisResult:
        domain = (domain or "").lower().strip(".")
        if not domain or "." not in domain:
            return WhoisResult(domain, error="not a domain")

        with self._cache_lock:
            if domain in self._cache:
                return self._cache[domain]
            lock = self._inflight.setdefault(domain, threading.Lock())

        with lock:                                  # one query per domain, ever
            with self._cache_lock:
                if domain in self._cache:
                    return self._cache[domain]
            result = self._lookup_uncached(domain)
            with self._cache_lock:
                self._cache[domain] = result
            return result

    def _lookup_uncached(self, domain: str) -> WhoisResult:
        tld = domain.rsplit(".", 1)[-1]
        server = KNOWN_TLD_SERVERS.get(tld) or self._server_for_tld(tld)
        if not server:
            return WhoisResult(domain, error=f"no whois server for .{tld}")

        try:
            raw = self._ask(server, domain)
        except OSError as exc:
            return WhoisResult(domain, error=f"{type(exc).__name__}", server=server)

        result = _parse(domain, raw, server)

        # Thin registries hand off to the registrar for the real record.
        referral = _referral_server(raw)
        if referral and referral != server:
            try:
                raw2 = self._ask(referral, domain)
                if raw2 and len(raw2) > 40:
                    deeper = _parse(domain, raw2, referral)
                    result = _merge(result, deeper)
            except OSError:
                pass  # registry answer is still useful

        return result

    def _server_for_tld(self, tld: str) -> str:
        try:
            raw = self._ask(IANA_SERVER, tld)
        except OSError:
            return ""
        # IANA answers gTLDs with "refer:" and most ccTLDs with "whois:".
        m = re.search(r"^(?:refer|whois):\s*(\S+)", raw, re.I | re.M)
        return m.group(1).strip().rstrip(".").lower() if m else ""

    def _throttle(self, server: str) -> None:
        while True:
            with self._server_lock:
                now = time.monotonic()
                ready = self._next_ok.get(server, 0.0)
                if now >= ready:
                    self._next_ok[server] = now + self.per_server_delay
                    return
                wait = ready - now
            time.sleep(min(wait, 5.0))

    def _ask(self, server: str, query: str) -> str:
        self._throttle(server)
        # Verisign needs "domain " to return the full record rather than a list.
        if server == "whois.verisign-grs.com":
            query = f"domain {query}"

        with socket.create_connection((server, 43), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            sock.sendall(query.encode("utf-8", "ignore") + b"\r\n")
            chunks: list[bytes] = []
            total = 0
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > 300_000:
                    break
        return b"".join(chunks).decode("utf-8", "replace")


def _referral_server(raw: str) -> str:
    for pattern in (r"^\s*registrar whois server:\s*(\S+)", r"^\s*whois server:\s*(\S+)",
                    r"^\s*whois:\s*(\S+)"):
        m = re.search(pattern, raw, re.I | re.M)
        if m:
            host = m.group(1).strip().rstrip(".").lower()
            host = re.sub(r"^https?://", "", host).split("/")[0]
            if "." in host and " " not in host:
                return host
    return ""


def _parse(domain: str, raw: str, server: str) -> WhoisResult:
    res = WhoisResult(domain, server=server, raw=raw)
    if not raw.strip():
        res.error = "empty response"
        return res

    low = raw.lower()
    if any(m in low for m in ("no match for", "not found", "no data found",
                             "no entries found", "domain not found",
                             "status: free", "no object found")):
        res.error = "no whois record"
        return res
    if "rate limit" in low or "too many requests" in low or "query limit" in low:
        res.error = "rate limited"
        return res

    # Some registries (.ch among them) refuse port-43 queries outright and
    # answer with a one-line notice. Judge by length so we never mistake a
    # registry's terms-of-use boilerplate for a refusal.
    if len(raw) < 600 and any(m in low for m in (
        "not permitted", "access denied", "request denied", "refused",
        "please use https://", "please use http://", "web-based whois",
    )):
        res.error = "registry refuses automated whois"
        return res

    res.ok = True
    res.redacted = any(m in low for m in REDACTION_MARKERS)

    kv_org, kv_emails, kv_ns, registrar, created, abuse = _parse_key_values(raw)
    blk_org, blk_emails, blk_ns = _parse_blocks(raw)

    res.org = _best_org(kv_org or blk_org)
    res.registrar = registrar
    res.created = created

    emails = _dedupe(kv_emails + blk_emails)
    if not emails:
        emails = _dedupe(e.lower() for e in _EMAIL_RE.findall(raw))
    # Registrar abuse mailboxes and privacy proxies are a last resort, never
    # the headline contact.
    real = [e for e in emails
            if e not in abuse and not _is_boilerplate_email(e) and not _is_proxy_email(e)]
    res.real_emails = real
    res.emails = real + [e for e in emails if e not in real]

    res.nameservers = _dedupe(n.lower() for n in (kv_ns + blk_ns))
    return res


def _parse_key_values(raw: str):
    orgs: list[str] = []
    emails: list[str] = []
    nameservers: list[str] = []
    abuse: set[str] = set()
    registrar = created = ""

    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower().lstrip("*% ")
        value = value.strip()
        if not value or value.startswith("//"):
            continue

        if key in _ABUSE_KEYS:
            for e in _EMAIL_RE.findall(value):
                abuse.add(e.lower())
                emails.append(e.lower())
        elif key in _EMAIL_KEYS or (key.endswith("email") and "@" in value):
            emails.extend(e.lower() for e in _EMAIL_RE.findall(value))
        elif key in _ORG_KEYS:
            orgs.append(value)
        elif key in _NS_KEYS:
            host = value.split()[0].strip(".").lower()
            if "." in host:
                nameservers.append(host)
        elif key == "registrar" and not registrar:
            registrar = value
        elif key in ("creation date", "created", "domain record activated") and not created:
            created = value

    return orgs, emails, nameservers, registrar, created, abuse


def _parse_blocks(raw: str):
    """Handle EDUCAUSE-style records: a header line, then indented values."""
    orgs: list[str] = []
    emails: list[str] = []
    nameservers: list[str] = []

    lines = raw.splitlines()
    headers = [(i, m.group(1).lower())
               for i, line in enumerate(lines)
               if (m := _BLOCK_RE.match(line.strip() and line or ""))]

    for idx, name in headers:
        body: list[str] = []
        for line in lines[idx + 1:]:
            if not line.strip():
                if body:
                    break
                continue
            if not line[:1].isspace():
                break
            body.append(line.strip())

        if name == "name servers":
            nameservers.extend(b.split()[0].strip(".").lower() for b in body if "." in b)
            continue

        for entry in body:
            found = _EMAIL_RE.findall(entry)
            if found:
                emails.extend(e.lower() for e in found)
        if name == "registrant":
            for entry in body:
                if "@" not in entry and not re.match(r"^[\d\s\-+().]+$", entry):
                    orgs.append(entry)
                    break

    return orgs, emails, nameservers


def _best_org(candidates: list[str]) -> str:
    for value in candidates:
        v = value.strip()
        if not v:
            continue
        if any(m in v.lower() for m in REDACTION_MARKERS):
            continue
        return v[:200]
    return ""


def _is_proxy_email(email: str) -> bool:
    """Hashed forwarding addresses handed out by privacy proxies."""
    local, _, domain = email.partition("@")
    if "whoisproxy" in domain or "privacy" in domain or "proxy" in domain:
        return True
    return bool(re.fullmatch(r"[0-9a-f]{24,}", local))


def _is_boilerplate_email(email: str) -> bool:
    return any(s in email for s in (
        "abuse@", "icann", "@verisign", "@iana", "report@", "compliance@",
        "noreply", "no-reply", "@educause.edu",
    ))


def _dedupe(items) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        item = item.strip()
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _merge(primary: WhoisResult, extra: WhoisResult) -> WhoisResult:
    """Registrar data wins where the registry was thin or redacted."""
    if not extra.ok:
        return primary
    merged = primary
    if extra.org and (not merged.org or merged.redacted):
        merged.org = extra.org
    merged.emails = _dedupe(merged.emails + extra.emails)
    merged.real_emails = _dedupe(merged.real_emails + extra.real_emails)
    merged.nameservers = _dedupe(merged.nameservers + extra.nameservers)
    merged.registrar = merged.registrar or extra.registrar
    merged.created = merged.created or extra.created
    merged.redacted = merged.redacted or extra.redacted
    merged.ok = True
    return merged
