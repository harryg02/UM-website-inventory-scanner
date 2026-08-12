# UM Website Inventory Scanner

Crawls `umich.edu`, logs every domain it links out to, and takes a position on
which of the external ones are actually University of Michigan properties.

Output is a single CSV with four columns:

| column | meaning |
| --- | --- |
| `domain` | the host (UM subdomains) or registrable domain (everything else) |
| `type` | `internal`, `external-affiliated`, `external-review`, `external-unrelated` |
| `whois_contact` | the technical contact's email address from the WHOIS record |
| `on_page_contact` | best email addresses scraped from the homepage and `/contact` |

`whois_contact` is the **technical contact** address — the party who actually
runs the domain. Records with no technical contact fall back to the
administrative then registrant address, and `--evidence` records which role
each address came from. A privacy-proxied or abuse-only record reports
`redacted` rather than passing off a registrar's abuse mailbox as a contact.

`--evidence` also keeps `source_url` (the page a domain was first seen on)
alongside the affiliation score, so provenance is still available for
debugging without cluttering the deliverable.

## Running it

```bash
python3 scan.py                          # full scan -> inventory.csv
python3 scan.py --max-pages 100 -v       # smaller, chatty run
python3 scan.py --max-pages 0            # crawl everything reachable
python3 scan.py --evidence audit.csv     # also write the scoring audit trail
python3 scan.py --skip-whois             # crawl + contacts only (much faster)
```

Core dependency is `requests` alone. WHOIS is spoken directly over port 43, so
there is no `python-whois` package or `whois` binary to install. HTML is parsed
with the standard library's `html.parser`.

### Browser rendering (optional, recommended)

Much of `umich.edu` — including the `www` seed — sits behind a Cloudflare
interstitial that plain HTTP cannot read, and some UM sites build their links
in JavaScript. Both are solved by rendering in a real browser:

```bash
python3 -m venv .venv
.venv/bin/pip install requests playwright
.venv/bin/playwright install chromium

.venv/bin/python scan.py --render        # escalate to a browser when needed
```

`--render` is a *fallback*, not the default engine: every page is tried over
plain HTTP first and only escalated when the response is a challenge page or a
link-less JavaScript shell. On a measured 30-page crawl that was 16 pages, of
which 15 recovered and 1 stayed blocked. `--render-all` renders everything
(much slower), `--render-wait` controls how long an interstitial is given to
resolve, and `--render-headful` shows the browser window.

The browser runs as a pool of `--render-workers` (default 3), each owning its
own Chromium. Playwright's sync API is bound to the thread that creates it, so
parallelism comes from independent workers sharing one job queue rather than
from sharing a browser. Six challenge-gated pages render in about two seconds
on a 3-worker pool.

`--render-crawl-only` uses the browser for link discovery but not for contact
pages. **No domain is skipped or dropped** — every domain still gets a WHOIS
lookup, an affiliation verdict and a CSV row. What you give up is on-page
evidence for external sites whose homepage is challenge-blocked, which can move
a domain from `external-affiliated` down to `external-review`. Use it when you
want discovery breadth quickly; leave it off for the most confident
classification.

Without Playwright installed the flag prints install instructions and the scan
continues over plain HTTP, so nothing breaks.

Ctrl-C at any point still writes the rows collected so far.

```bash
python3 test_umscan.py    # 24 offline tests, no network needed
```

## How the crawl behaves

- Starts at `https://www.umich.edu/`.
- Follows `*.umich.edu` links recursively; marks them `internal`.
- Logs external links once, marks them external, and never follows them.
- Caps each host at 10 pages (`--pages-per-domain`), 2000 pages overall
  (`--max-pages`; pass `0` to crawl until the frontier is exhausted).
- Skips noise entirely: Google, LinkedIn, Facebook, CDNs, analytics, scholarly
  plumbing like `doi.org`, and **every `.edu` that isn't UM**. Noise domains are
  not logged, not looked up, and not followed.
- Ignores `robots.txt` by design, but keeps a per-host delay (`--delay`,
  default 0.4s) so it stays polite in practice.
- Isolates faults per page and per domain. A malformed link, an unparseable
  response or a single failing WHOIS lookup is recorded and skipped -- it never
  aborts a run that may have taken an hour. Ctrl-C still writes what has been
  collected so far.

Internal domains key on the full host, so `lsa.umich.edu` and
`lib.umich.edu` are separate inventory rows — that is the point of the
inventory. External domains key on the registrable domain, so `example.com`
and `www.example.com` collapse into one row.

## The hard part: is an external domain UM or not?

Plenty of UM-affiliated sites live on `.org` and `.com`, and plenty of
unrelated sites mention Michigan. There is no clean test, so the scanner
scores several independent signals and buckets the total
(`umscan/affiliation.py`):

| signal | weight |
| --- | --- |
| WHOIS registrant is "Regents of the University of Michigan" | +7 |
| WHOIS registrant names UM or Michigan Medicine | +6 |
| WHOIS contact email under `umich.edu` | +5 |
| Nameservers run by UM (`*.umich.*`) | +4 |
| `umich.edu` email published on the site | +4 |
| Domain contains `umich` / `michiganmedicine` (`mgoblue`, `goblue` +3, `michigan` +1) | +4 |
| "Regents of the University of Michigan" in page text | +4 |
| Page names UM repeatedly / once | +3 / +2 |
| Page links back to `umich.edu` | +2 |
| Ann Arbor address on the page | +1 |
| WHOIS registrant is a *different* Michigan institution | −6 |
| Page is mostly about another Michigan institution | −2 |

Score ≥ 6 is `external-affiliated`, 3–5 is `external-review`, below that is
`external-unrelated`. The middle bucket is deliberate: an MVP should hand
ambiguous domains to a human instead of guessing. Run with `--evidence` to get
the per-domain score and the exact signals behind it.

**Page evidence carries more weight than WHOIS.** Registrant data is
privacy-redacted on most `.com`/`.org` domains now, so WHOIS rarely settles
anything on its own -- it contributes mostly through nameservers. Measured on
four known UM properties:

| domain | pages only | WHOIS only | both |
| --- | --- | --- | --- |
| `uofmhealth.org` | affiliated (9) | review (4) | affiliated (9) |
| `michiganmedicine.org` | affiliated (10) | review (4) | affiliated (10) |
| `ums.org` | affiliated (7) | review (4) | affiliated (11) |
| `michigandaily.com` | affiliated (11) | unrelated (1) | affiliated (11) |

Page evidence alone classified all four; WHOIS alone classified none. If you
need to trade something away for speed, use `--skip-whois` rather than
`--skip-contacts` -- WHOIS is also the rate-limited half. The two are
independent: either can be skipped without affecting the other.

Two real examples of why the multi-signal approach matters:

- `michiganradio.org` — WHOIS registrant is redacted behind a privacy proxy,
  but its nameservers are `cffw1.dns.umich.com` and the site names UM. Scores
  10, correctly affiliated.
- `michigan.gov` — has "michigan" in the name and nothing else. Scores 0.

## Tuning coverage

Domain discovery is bounded by the page budget, not by the crawler running out
of links. Measured, crawl-only, with `--render`:

| pages | domains found | wall time |
| --- | --- | --- |
| 30 | 162 | seconds |
| 60 | ~208 | seconds |
| 800 | 895 (507 internal, 388 external) | 6 min |
| 4000 | **2203** (903 internal, 1300 external) | 41 min |

Every one of those runs stopped on the page cap, not on an empty frontier --
including the 4000-page one. Discovery was still climbing when each ended, so
if a run looks shallow, raise `--max-pages` (or set it to `0`) before
suspecting the crawl logic. Throughput is roughly 1.6 pages/second with a
4-worker browser pool.

Two other levers matter:

- `--pages-per-domain` (default 10) trades depth-per-host for breadth. Raising
  it finds more within large sites like `lsa.umich.edu`.
- The noise list excludes Google, social, CDNs and **every non-UM `.edu`**. The
  4000-page crawl skipped 14,072 links across 198 noise domains -- those would
  add ~9% to a raw domain count. Scanners that count everything will report a
  larger number for the same crawl; the totals are not measuring the same thing.

A crawler can only find hosts that something links to. Hosts nothing links to
need enumeration rather than crawling -- Certificate Transparency logs
(`crt.sh`) list every `*.umich.edu` name that has ever been issued a
certificate, and would seed the crawl far more completely than the link graph
alone.

## Bot protection, and where this tool stops

`www.umich.edu` and many sibling hosts (`lsa`, `news`, `record`, `admissions`,
`provost`, …) answer a plain HTTP client with a `403` Cloudflare interstitial
instead of HTML.

With `--render`, Chromium loads the page, runs the challenge script, and the
interstitial resolves on its own. Challenge-blocked hosts dropped from 19 to 1
and the inventory went from 80 domains to 208. The browser sends the same
self-identifying user agent as the HTTP client (`…UM-Inventory-Scanner/0.1`);
nothing is disguised.

It is not a complete fix: 18 of 116 render attempts stayed on the challenge
page and are reported as such. Some Cloudflare configurations do not resolve
without interaction, and that is where this tool stops.

**What this tool will not do:** patch `navigator.webdriver`, spoof TLS or
canvas fingerprints, install stealth plugins, rotate residential proxies, or
call a CAPTCHA-solving service. `umscan/render.py` renders the page and waits,
bounded by `--render-wait`. A challenge that does not clear on its own is
reported as `challenge did not clear in browser` and the host stays
uncrawled. If Cloudflare tightens its policy, the correct response is an
allowlist from UM ITS — not more aggressive evasion. For a tool inventorying
the institution that runs the WAF, that is the right conversation anyway.

Without `--render`, a blocked seed no longer kills the run: the crawler falls
back to UM hosts that serve ordinary HTML (`FALLBACK_SEEDS` in
`umscan/config.py`). Disable with `--no-fallback`. The summary always reports
which path was taken and how many hosts stayed blocked.

## What a real run looks like

Same 60-page budget, with and without the browser fallback. Both fully
profiled (WHOIS + contact pages):

| | plain HTTP | `--render` |
| --- | --- | --- |
| seed reachable | no — used fallback hosts | **yes** |
| pages parsed | 43 / 60 | **58 / 60** |
| challenge-blocked hosts | 19 | **1** |
| domains inventoried | 80 | **208** |
| internal | 52 | **168** |
| affiliated / review / unrelated | 6 / 4 / 18 | **9 / 7 / 24** |
| browser renders | — | 116 attempted, 91 recovered, 18 still blocked |
| wall clock | 134s | 356s |

The affiliated set from the rendered run — not one of these is on `umich.edu`:

```
michigandaily.com      ums.org               michiganmedicine.org
umjobs.org             sindecusemuseum.org   mgoblue.com
michiganpublic.org     myumi.ch              urcmich.org
```

Every one has a redacted or unhelpful WHOIS record. They were caught by UM
nameservers, `@umich.edu` addresses published on the page
(`dentalmuseum@umich.edu`, `bpilz@umich.edu`), and copyright text — which is
the entire argument for scoring several signals rather than trusting WHOIS.

The review bucket earns its keep as well. It held `theconversation.com` and
`wilx.com`, which publish UM stories without being UM, next to `mden.com`,
the licensed merchandise retailer — genuinely arguable calls that belong in
front of a human instead of inside a guess.

Rendering costs time: one browser serves every worker, so renders serialise.
Use `--skip-whois` while iterating on the crawl, and expect a fully profiled
`--render` run over hundreds of domains to take minutes rather than seconds.

## Layout

```
scan.py               entry point
umscan/
  config.py           seeds, noise lists, tunables
  urls.py             normalisation, eTLD+1, internal/external/noise classification
  fetch.py            polite HTTP with size caps and challenge detection
  extract.py          stdlib HTML parsing: links, text, emails (incl. "name at x dot edu")
  whois.py            port-43 WHOIS client, referral chasing, registrant parsing
  affiliation.py      the UM-relatedness scorer
  crawl.py            breadth-first crawl with the per-host page cap
  profile.py          per-domain WHOIS + homepage/contact enrichment
  render.py           optional Playwright fallback + escalation policy
  report.py           CSV writer and run summary
test_umscan.py        offline tests for URL, extraction, scoring and WHOIS parsing
```
