"""Write the inventory CSV and print a short summary."""

from __future__ import annotations

import csv
import sys

from . import urls as u
from .affiliation import AFFILIATED, REVIEW, UNRELATED

COLUMNS = ["domain", "type", "whois_contact", "on_page_contact"]

EVIDENCE_COLUMNS = [
    "domain", "type", "score", "signals", "whois_contact", "whois_role",
    "on_page_contact", "source_url", "notes",
]

TYPE_ORDER = {u.INTERNAL: 0, AFFILIATED: 1, REVIEW: 2, UNRELATED: 3}


def sort_key(profile):
    return (TYPE_ORDER.get(profile.type, 9), -profile.score, profile.domain)


def write_csv(profiles: list, path: str) -> int:
    rows = sorted(profiles, key=sort_key)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(COLUMNS)
        for p in rows:
            writer.writerow([p.domain, p.type, p.whois_contact, p.on_page_contact])
    return len(rows)


def write_evidence_csv(profiles: list, path: str) -> int:
    rows = sorted(profiles, key=sort_key)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(EVIDENCE_COLUMNS)
        for p in rows:
            writer.writerow([p.domain, p.type, p.score, p.reason, p.whois_contact,
                             p.whois_role, p.on_page_contact, p.source_url,
                             p.fetch_note])
    return len(rows)


def summarize(crawl_result, profiles: list, out=sys.stdout,
              render_stats: dict | None = None) -> None:
    counts: dict[str, int] = {}
    for p in profiles:
        counts[p.type] = counts.get(p.type, 0) + 1

    print("", file=out)
    print("=" * 62, file=out)
    print("Crawl", file=out)
    print(f"  pages fetched      : {crawl_result.pages_fetched}", file=out)
    print(f"  pages parsed       : {crawl_result.pages_ok}", file=out)
    if crawl_result.failures:
        detail = ", ".join(f"{k}={v}" for k, v in crawl_result.failures.most_common())
        print(f"  fetch failures     : {detail}", file=out)
    if crawl_result.blocked_hosts:
        print(f"  bot-protected hosts: {len(crawl_result.blocked_hosts)} "
              f"(challenge pages, not crawlable)", file=out)
    if getattr(crawl_result, "used_fallback", False):
        print("  NOTE               : primary seed was blocked; "
              "crawled from fallback UM hosts", file=out)
    noise_total = sum(crawl_result.noise_skipped.values())
    print(f"  noise links skipped: {noise_total} "
          f"({len(crawl_result.noise_skipped)} domains)", file=out)

    if render_stats and render_stats["attempted"]:
        print(f"  browser renders    : {render_stats['succeeded']}/"
              f"{render_stats['attempted']} recovered"
              + (f", {render_stats['still_blocked']} still blocked"
                 if render_stats["still_blocked"] else ""), file=out)

    print("Inventory", file=out)
    for label in (u.INTERNAL, AFFILIATED, REVIEW, UNRELATED):
        if counts.get(label):
            print(f"  {label:20s}: {counts[label]}", file=out)
    print(f"  {'total':20s}: {len(profiles)}", file=out)

    flagged = [p for p in profiles if p.type == REVIEW]
    if flagged:
        print("", file=out)
        print("Needs a human eye (ambiguous UM affiliation):", file=out)
        for p in sorted(flagged, key=lambda x: -x.score)[:15]:
            print(f"  {p.domain:38s} score={p.score:<3d} {p.reason}", file=out)
    print("=" * 62, file=out)
