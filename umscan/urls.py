"""URL normalisation, registrable-domain extraction, and link classification."""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

from .config import (
    INTERNAL_SUFFIXES,
    NOISE_DOMAINS,
    NOISE_HOST_MARKERS,
    SKIP_EXTENSIONS,
)

# Two-label public suffixes we care about. Not the full PSL, but enough that
# "bbc.co.uk" doesn't collapse to "co.uk" on an MVP crawl.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz", "ac.nz", "govt.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "ac.in", "gov.in",
    "com.br", "com.mx", "com.ar", "com.co", "com.pe",
    "com.cn", "edu.cn", "gov.cn", "net.cn", "org.cn",
    "co.za", "org.za", "com.sg", "edu.sg", "co.kr", "or.kr",
    "com.tr", "edu.tr", "com.tw", "edu.tw", "com.hk", "edu.hk",
    "co.il", "ac.il", "org.il", "com.my", "edu.my", "co.th", "ac.th",
    "com.ua", "com.pl", "com.ph", "edu.ph", "co.id", "ac.id", "com.vn",
}

INTERNAL = "internal"
EXTERNAL = "external"
NOISE = "noise"
INVALID = "invalid"


def normalize_url(url: str, base: str | None = None) -> str | None:
    """Absolutise, strip the fragment, and canonicalise a link.

    Returns None for anything we cannot or should not fetch.
    """
    if not url:
        return None
    url = url.strip()
    if not url or url.startswith("#"):
        return None

    low = url.lower()
    for bad in ("javascript:", "mailto:", "tel:", "data:", "file:", "sms:", "callto:", "ftp:"):
        if low.startswith(bad):
            return None

    if base:
        url = urljoin(base, url)
    url, _ = urldefrag(url)

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return None

    host = (parts.hostname or "").lower().strip(".")
    if not host or "." not in host:
        return None

    # Drop the default port, keep any non-default one.
    netloc = host
    if parts.port and not (
        (parts.scheme == "http" and parts.port == 80)
        or (parts.scheme == "https" and parts.port == 443)
    ):
        netloc = f"{host}:{parts.port}"

    path = parts.path or "/"
    return urlunsplit((parts.scheme, netloc, path, parts.query, ""))


def host_of(url: str) -> str:
    """Lowercased hostname with any leading 'www.' preserved."""
    return (urlsplit(url).hostname or "").lower().strip(".")


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 using a small built-in suffix list."""
    host = (host or "").lower().strip(".")
    if not host:
        return ""
    if is_ip_literal(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_internal_host(host: str) -> bool:
    host = (host or "").lower().strip(".")
    return any(host == suf or host.endswith("." + suf) for suf in INTERNAL_SUFFIXES)


def is_noise_host(host: str) -> bool:
    """Noise = big platforms, infrastructure, and every non-UM .edu."""
    host = (host or "").lower().strip(".")
    if not host or is_ip_literal(host) or host.endswith(".local") or host == "localhost":
        return True

    reg = registrable_domain(host)
    if reg in NOISE_DOMAINS or host in NOISE_DOMAINS:
        return True

    # Any .edu that isn't UM is somebody else's campus: log-worthy noise.
    if host.endswith(".edu") and not is_internal_host(host):
        return True

    # Sub-hosts of a noise domain (docs.google.com, maps.google.com, ...).
    if any(reg == d or reg.endswith("." + d) for d in NOISE_DOMAINS):
        return True

    if any(host.startswith(m) for m in NOISE_HOST_MARKERS):
        return True

    return False


def has_skippable_extension(url: str) -> bool:
    path = urlsplit(url).path
    ext = os.path.splitext(path)[1].lower()
    return bool(ext) and ext in SKIP_EXTENSIONS


def classify(url: str) -> tuple[str, str]:
    """Return (kind, domain_key) for a normalised URL.

    Internal domains key on the full host so each UM subdomain is its own
    inventory row; external domains key on the registrable domain so
    www.example.com and example.com collapse into one.
    """
    host = host_of(url)
    if not host:
        return INVALID, ""
    if is_internal_host(host):
        return INTERNAL, host
    if is_noise_host(host):
        return NOISE, registrable_domain(host)
    return EXTERNAL, registrable_domain(host)
