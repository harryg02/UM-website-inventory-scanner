"""Enrich each discovered domain: WHOIS record + on-page contact addresses."""

from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urljoin

from . import urls as u
from .affiliation import Evidence, assess
from .config import CONTACT_PATHS, Settings
from .crawl import DomainHit
from .extract import Page
from .fetch import CHALLENGED, Fetcher
from .whois import WhoisClient


@dataclass
class DomainProfile:
    """One row of the final inventory."""

    domain: str
    type: str
    whois_contact: str
    on_page_contact: str
    source_url: str
    whois_role: str = ""
    score: int = 0
    reason: str = ""
    fetch_note: str = ""


class Profiler:
    def __init__(self, settings: Settings, fetcher: Fetcher, whois: WhoisClient):
        self.s = settings
        self.fetcher = fetcher
        self.whois = whois
        self.completed: list[DomainProfile] = []
        self._print_lock = threading.Lock()

    def log(self, msg: str) -> None:
        if self.s.verbose:
            with self._print_lock:
                print(msg, file=sys.stderr, flush=True)

    def run(self, hits: list[DomainHit]) -> list[DomainProfile]:
        """Profile every domain. `completed` survives a Ctrl-C mid-run."""
        self.completed: list[DomainProfile] = []
        workers = max(1, self.s.profile_workers)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.profile, hit): hit for hit in hits}
            try:
                for future in as_completed(futures):
                    try:
                        self.completed.append(future.result())
                    except Exception as exc:      # keep the row, note the failure
                        self.completed.append(_failed(futures[future], exc))
            except KeyboardInterrupt:
                for future in futures:
                    future.cancel()
                raise
        return self.completed

    def profile(self, hit: DomainHit) -> DomainProfile:
        ev = Evidence(domain=hit.domain)
        notes: list[str] = []

        if not self.s.skip_whois:
            record = self.whois.lookup(u.registrable_domain(hit.domain))
            whois_contact = record.contact()
            whois_role = record.contact_role
            ev.whois_org = record.org
            ev.whois_emails = list(record.emails)
            ev.nameservers = list(record.nameservers)
        else:
            whois_contact = whois_role = ""

        page_emails: list[str] = []
        if not self.s.skip_contacts:
            page_emails, note = self._gather_contacts(hit, ev)
            if note:
                notes.append(note)
        ev.page_emails = page_emails

        if hit.kind == u.INTERNAL:
            dtype, score, reason = u.INTERNAL, 0, "umich.edu subdomain"
        else:
            verdict = assess(ev)
            dtype, score, reason = verdict.label, verdict.score, verdict.reason

        profile = DomainProfile(
            domain=hit.domain,
            type=dtype,
            whois_contact=whois_contact,
            on_page_contact=self._best_contacts(page_emails, hit.domain),
            source_url=hit.source_url,
            whois_role=whois_role,
            score=score,
            reason=reason,
            fetch_note="; ".join(notes),
        )
        self.log(f"[profile] {profile.type:20s} {profile.domain}")
        return profile

    def _gather_contacts(self, hit: DomainHit, ev: Evidence) -> tuple[list[str], str]:
        """Homepage first, then /contact -- exactly as far as we need to go."""
        emails: list[str] = []
        text_parts: list[str] = []
        note = ""

        for base_url in self._homepage_candidates(hit):
            resp = self.fetcher.get(base_url, retries=0)
            if not resp.usable:
                if resp.status == CHALLENGED and not note:
                    note = "homepage behind bot protection"
                continue

            page = Page(resp.text)
            emails.extend(page.emails())
            text_parts.append(page.text[:20000])
            ev.links_to_umich = ev.links_to_umich or self._links_to_umich(page, resp.final_url or base_url)
            home = resp.final_url or base_url

            if not emails:
                for path in CONTACT_PATHS[: max(0, self.s.contact_paths)]:
                    cresp = self.fetcher.get(urljoin(home, path), retries=0)
                    if not cresp.usable:
                        continue
                    cpage = Page(cresp.text)
                    found = cpage.emails()
                    text_parts.append(cpage.text[:20000])
                    ev.links_to_umich = ev.links_to_umich or self._links_to_umich(
                        cpage, cresp.final_url or cresp.url
                    )
                    if found:
                        emails.extend(found)
                        break
            break

        ev.page_text = " ".join(text_parts)
        if not emails and not text_parts and not note:
            note = "site unreachable"
        return _dedupe(emails), note

    def _homepage_candidates(self, hit: DomainHit) -> list[str]:
        if hit.kind == u.INTERNAL:
            return [f"https://{hit.domain}/"]
        return [f"https://{hit.domain}/", f"https://www.{hit.domain}/"]

    @staticmethod
    def _links_to_umich(page: Page, base: str) -> bool:
        for raw in page.links[:400]:
            target = u.normalize_url(raw, base)
            if target and u.is_internal_host(u.host_of(target)):
                return True
        return False

    @staticmethod
    def _best_contacts(emails: list[str], domain: str, limit: int = 2) -> str:
        """Rank addresses so the most telling one lands in the CSV first."""
        def rank(email: str) -> tuple:
            edomain = email.split("@", 1)[-1]
            umich = edomain == "umich.edu" or edomain.endswith(".umich.edu")
            same_site = edomain == domain or edomain.endswith("." + domain)
            generic = email.split("@", 1)[0] in {
                "info", "contact", "hello", "help", "support", "admin",
                "office", "webmaster", "inquiries",
            }
            return (not umich, not same_site, not generic, len(email))

        return "; ".join(sorted(emails, key=rank)[:limit])


def _failed(hit: DomainHit, exc: Exception) -> DomainProfile:
    """A domain we could not profile still belongs in the inventory."""
    reason = f"{type(exc).__name__}: {exc}"[:160]
    return DomainProfile(
        domain=hit.domain,
        # An unscored external domain is unknown, not unrelated.
        type=u.INTERNAL if hit.kind == u.INTERNAL else "external-review",
        whois_contact="",
        on_page_contact="",
        source_url=hit.source_url,
        reason=f"profiling failed ({reason})",
        fetch_note=reason,
    )


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
