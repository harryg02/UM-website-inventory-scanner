"""Breadth-first crawl of umich.edu that logs every domain it meets once."""

from __future__ import annotations

import sys
import threading
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urljoin

from . import urls as u
from .config import Settings
from .extract import Page
from .fetch import CHALLENGED, Fetcher, Response


@dataclass
class DomainHit:
    """A domain the crawl discovered, plus where we first saw it."""

    domain: str
    kind: str                 # u.INTERNAL or u.EXTERNAL
    source_url: str           # page that linked to it
    example_url: str          # the link target itself
    times_seen: int = 1


@dataclass
class CrawlResult:
    domains: dict = field(default_factory=dict)
    pages_fetched: int = 0
    pages_ok: int = 0
    blocked_hosts: set = field(default_factory=set)
    used_fallback: bool = False
    failures: Counter = field(default_factory=Counter)
    noise_skipped: Counter = field(default_factory=Counter)

    @property
    def internal(self) -> list:
        return [d for d in self.domains.values() if d.kind == u.INTERNAL]

    @property
    def external(self) -> list:
        return [d for d in self.domains.values() if d.kind == u.EXTERNAL]


class Crawler:
    def __init__(self, settings: Settings, fetcher: Fetcher):
        self.s = settings
        self.fetcher = fetcher
        self.result = CrawlResult()
        self._print_lock = threading.Lock()

    def log(self, msg: str) -> None:
        if self.s.verbose:
            with self._print_lock:
                print(msg, file=sys.stderr, flush=True)

    def run(self) -> CrawlResult:
        frontier: deque[str] = deque()
        queued: set[str] = set()
        pages_by_host: Counter = Counter()

        self._seed(self.s.seeds, frontier, queued)

        with ThreadPoolExecutor(max_workers=self.s.crawl_workers) as pool:
            self._loop(pool, frontier, queued, pages_by_host)

            # The front door was bolted: re-enter through hosts that answer.
            if self.result.pages_ok == 0 and self.s.fallback_seeds:
                self.log("[crawl] seed yielded no parseable page; "
                         "falling back to known UM entry points")
                self.result.used_fallback = True
                self._seed(self.s.fallback_seeds, frontier, queued)
                self._loop(pool, frontier, queued, pages_by_host)

        return self.result

    def _seed(self, seeds: list, frontier: deque, queued: set) -> None:
        for seed in seeds:
            norm = u.normalize_url(seed)
            if norm and norm not in queued:
                queued.add(norm)
                frontier.append(norm)
                self._record(norm, "seed")

    def _page_budget_spent(self) -> bool:
        """max_pages of 0 means crawl until the frontier runs dry."""
        return bool(self.s.max_pages) and self.result.pages_fetched >= self.s.max_pages

    def _loop(self, pool, frontier: deque, queued: set, pages_by_host: Counter) -> None:
        batch_size = max(1, self.s.crawl_workers * 2)

        while frontier and not self._page_budget_spent():
            batch: list[str] = []
            while frontier and len(batch) < batch_size:
                if self.s.max_pages and \
                        self.result.pages_fetched + len(batch) >= self.s.max_pages:
                    break
                url = frontier.popleft()
                host = u.host_of(url)
                if pages_by_host[host] >= self.s.pages_per_domain:
                    continue
                pages_by_host[host] += 1
                batch.append(url)

            if not batch:
                break

            for resp in pool.map(self.fetcher.get, batch):
                self.result.pages_fetched += 1
                self._handle(resp, frontier, queued, pages_by_host)

            if self.s.max_domains and len(self.result.domains) >= self.s.max_domains:
                self.log(f"[crawl] domain cap {self.s.max_domains} reached")
                break

    def _handle(self, resp: Response, frontier: deque, queued: set,
                pages_by_host: Counter) -> None:
        host = u.host_of(resp.url)

        if not resp.usable:
            self.result.failures[resp.status] += 1
            if resp.status == CHALLENGED:
                self.result.blocked_hosts.add(host)
            self.log(f"[skip] {resp.status:12s} {resp.url} ({resp.note})")
            return

        self.result.pages_ok += 1
        page = Page(resp.text)
        base = resp.final_url or resp.url
        if page.base_href:
            base = urljoin(base, page.base_href)

        candidates = list(page.links)
        if page.meta_refresh:
            candidates.append(page.meta_refresh)

        found_new = 0
        for raw in candidates:
            target = u.normalize_url(raw, base)
            if not target:
                continue

            kind, key = u.classify(target)
            if kind == u.INVALID:
                continue
            if kind == u.NOISE:
                self.result.noise_skipped[key] += 1
                continue

            if self._record(target, resp.url):
                found_new += 1

            if kind != u.INTERNAL:
                continue                      # externals are logged, never followed
            if target in queued or u.has_skippable_extension(target):
                continue
            if pages_by_host[u.host_of(target)] >= self.s.pages_per_domain:
                continue
            queued.add(target)
            frontier.append(target)

        self.log(
            f"[page] {resp.http_status} {resp.url} "
            f"links={len(candidates)} new_domains={found_new} "
            f"total={len(self.result.domains)} fetched={self.result.pages_fetched}"
        )

    def _record(self, target: str, source_url: str) -> bool:
        """Log a domain the first time we see it. Returns True if it was new."""
        kind, key = u.classify(target)
        if kind in (u.NOISE, u.INVALID) or not key:
            return False

        hit = self.result.domains.get(key)
        if hit:
            hit.times_seen += 1
            return False

        if self.s.max_domains and len(self.result.domains) >= self.s.max_domains:
            return False

        self.result.domains[key] = DomainHit(
            domain=key, kind=kind, source_url=source_url, example_url=target
        )
        return True
