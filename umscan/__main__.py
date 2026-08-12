"""Command line entry point: crawl umich.edu, then profile what it found."""

from __future__ import annotations

import argparse
import sys
import time

from . import report
from . import urls as u
from .config import FALLBACK_SEEDS, SEED_URLS, Settings
from .crawl import Crawler
from .fetch import Fetcher
from .profile import Profiler
from .whois import WhoisClient


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="umscan",
        description="Crawl umich.edu, inventory every domain it links to, and "
                    "flag which external domains look UM-affiliated.",
    )
    p.add_argument("--seed", action="append", default=None, metavar="URL",
                   help=f"start URL (repeatable; default {SEED_URLS[0]})")
    p.add_argument("-o", "--output", default="inventory.csv",
                   help="CSV path (default: inventory.csv)")
    p.add_argument("--evidence", default="", metavar="PATH",
                   help="also write an audit CSV with scores and signals")
    p.add_argument("--pages-per-domain", type=int, default=10,
                   help="page cap per host (default: 10)")
    p.add_argument("--max-pages", type=int, default=400,
                   help="total pages to fetch (default: 400)")
    p.add_argument("--max-domains", type=int, default=0,
                   help="stop after discovering this many domains (0 = no cap)")
    p.add_argument("--crawl-workers", type=int, default=8)
    p.add_argument("--profile-workers", type=int, default=6)
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--delay", type=float, default=0.4,
                   help="minimum seconds between hits on one host")
    p.add_argument("--contact-paths", type=int, default=2,
                   help="how many /contact variants to try (default: 2)")
    p.add_argument("--render", action="store_true",
                   help="escalate to a real browser for challenge pages and JS-only sites")
    p.add_argument("--render-all", action="store_true",
                   help="render every page in the browser (slow; implies --render)")
    p.add_argument("--render-wait", type=float, default=15.0,
                   help="seconds to let an interstitial resolve itself (default: 15)")
    p.add_argument("--render-headful", action="store_true",
                   help="run the browser with a visible window")
    p.add_argument("--no-fallback", action="store_true",
                   help="do not fall back to known UM hosts when the seed is blocked")
    p.add_argument("--skip-whois", action="store_true")
    p.add_argument("--skip-contacts", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def settings_from_args(args) -> Settings:
    return Settings(
        seeds=args.seed or list(SEED_URLS),
        fallback_seeds=[] if args.no_fallback else list(FALLBACK_SEEDS),
        pages_per_domain=args.pages_per_domain,
        max_pages=args.max_pages,
        max_domains=args.max_domains,
        crawl_workers=args.crawl_workers,
        profile_workers=args.profile_workers,
        http_timeout=args.timeout,
        per_host_delay=args.delay,
        contact_paths=args.contact_paths,
        skip_whois=args.skip_whois,
        skip_contacts=args.skip_contacts,
        output=args.output,
        evidence_output=args.evidence,
        verbose=args.verbose,
    )


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    s = settings_from_args(args)

    plain = Fetcher(timeout=s.http_timeout, per_host_delay=s.per_host_delay,
                    max_bytes=s.max_bytes,
                    pool=max(s.crawl_workers, s.profile_workers) * 2)
    fetcher = plain
    hybrid = None

    if args.render or args.render_all:
        from .render import (HybridFetcher, INSTALL_HINT, PlaywrightFetcher,
                             playwright_available)
        renderer = PlaywrightFetcher(timeout=s.http_timeout + 10,
                                     challenge_wait=args.render_wait,
                                     headless=not args.render_headful)
        if renderer.start():
            hybrid = HybridFetcher(plain, renderer, force=args.render_all)
            fetcher = hybrid
            print("[render] browser fallback active", file=sys.stderr)
        else:
            print(f"[render] disabled: {renderer.error}", file=sys.stderr)
            if not playwright_available():
                print(INSTALL_HINT, file=sys.stderr)
    whois = WhoisClient(timeout=s.whois_timeout)
    crawler = Crawler(s, fetcher)
    profiler = Profiler(s, fetcher, whois)

    started = time.monotonic()
    print(f"[1/2] crawling from {', '.join(s.seeds)} "
          f"(max {s.max_pages} pages, {s.pages_per_domain}/host)", file=sys.stderr)

    profiles = []
    try:
        crawl_result = crawler.run()
        hits = sorted(crawl_result.domains.values(),
                      key=lambda h: (h.kind != u.INTERNAL, h.domain))
        print(f"[2/2] profiling {len(hits)} domains "
              f"(whois{' skipped' if s.skip_whois else ''} + contact pages)",
              file=sys.stderr)
        profiles = profiler.run(hits)
    except KeyboardInterrupt:
        print("\ninterrupted -- writing what was collected so far", file=sys.stderr)
        crawl_result = crawler.result
        profiles = profiler.completed or [
            _stub(hit) for hit in crawl_result.domains.values()
        ]
    finally:
        fetcher.close()

    written = report.write_csv(profiles, s.output)
    report.summarize(crawl_result, profiles,
                     render_stats=hybrid.stats() if hybrid else None)
    elapsed = time.monotonic() - started
    print(f"wrote {written} rows to {s.output} in {elapsed:.1f}s", file=sys.stderr)

    if s.evidence_output:
        report.write_evidence_csv(profiles, s.evidence_output)
        print(f"wrote audit trail to {s.evidence_output}", file=sys.stderr)
    return 0


def _stub(hit):
    from .profile import DomainProfile
    return DomainProfile(domain=hit.domain, type=hit.kind, whois_contact="",
                         on_page_contact="", source_url=hit.source_url,
                         reason="not profiled (interrupted)")


if __name__ == "__main__":
    sys.exit(main())
