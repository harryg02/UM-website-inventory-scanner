# UM Website Inventory Scanner

Crawls `umich.edu`, logs every domain it links out to, and takes a position on
which of the external ones are actually University of Michigan properties.

Output is a single CSV with five columns:

| column | meaning |
| --- | --- |
| `domain` | the host (UM subdomains) or registrable domain (everything else) |
| `type` | `internal`, `external-affiliated`, `external-review`, `external-unrelated` |
| `whois_contact` | registrant org and/or email from the WHOIS record |
| `on_page_contact` | best email addresses scraped from the homepage and `/contact` |
| `source_url` | the page where this domain was first seen |

## Running it

```bash
python3 scan.py                          # full scan -> inventory.csv
python3 scan.py --max-pages 100 -v       # smaller, chatty run
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
- Caps each host at 10 pages (`--pages-per-domain`), 400 pages overall
  (`--max-pages`).
- Skips noise entirely: Google, LinkedIn, Facebook, CDNs, analytics, scholarly
  plumbing like `doi.org`, and **every `.edu` that isn't UM**. Noise domains are
  not logged, not looked up, and not followed.
- Ignores `robots.txt` by design, but keeps a per-host delay (`--delay`,
  default 0.4s) so it stays polite in practice.

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

Two real examples of why the multi-signal approach matters:

- `michiganradio.org` — WHOIS registrant is redacted behind a privacy proxy,
  but its nameservers are `cffw1.dns.umich.com` and the site names UM. Scores
  10, correctly affiliated.
- `michigan.gov` — has "michigan" in the name and nothing else. Scores 0.

## Bot protection, and where this tool stops

`www.umich.edu` and many sibling hosts (`lsa`, `news`, `record`, `admissions`,
`provost`, …) answer a plain HTTP client with a `403` Cloudflare interstitial
instead of HTML.

With `--render`, Chromium loads the page, runs the challenge script, and the
interstitial resolves on its own — the seed becomes crawlable and the
inventory roughly triples. The browser sends the same self-identifying user
agent as the HTTP client (`…UM-Inventory-Scanner/0.1`); nothing is disguised.

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

**Plain HTTP, seed blocked, fallback path** — 80 pages, 134 seconds, fully
profiled:

```
internal            : 52
external-affiliated : 6      michigandaily.com, ums.org, a2ru.org,
                             michiganpublic.org, lcbrd.com, tpluseplusaplusm.us
external-review     : 4      michiganmedicine.org, dimensionsjournal.us,
                             taubmanacdcc.com, rvtr.com
external-unrelated  : 18
noise links skipped : 411 across 26 domains
bot-protected hosts : 19
```

**With `--render`, from the real seed** — the crawl reaches far more of the
university, because `www.umich.edu` and its heavily-linked siblings become
readable:

```
30 pages   -> 162 domains (134 internal), 16 browser renders, 15 recovered
60 pages   -> ~208 domains        (vs 80 domains for 60 pages without --render)
```

Rendering roughly triples domain discovery at the same page budget. It also
costs real time: the browser is a single serialized worker, so a fully
profiled `--render` run over hundreds of domains takes considerably longer
than the 134 seconds above. Use `--skip-whois` while iterating.

The affiliated set is the interesting part — none of those domains are on
`umich.edu`, and only two have "michigan" in the name:

- `ums.org` (University Musical Society) — registrant redacted, but UM
  nameservers and `umstix@umich.edu` on the page.
- `a2ru.org` — `a2ruconnect@umich.edu` on the contact page.
- `tpluseplusaplusm.us` — WHOIS registrant is a UM faculty member
  (`afure@umich.edu`).
- `lcbrd.com` — behind a privacy proxy, but publishes
  `lcbrd.initiative@umich.edu`.

`michiganmedicine.org` landing in `external-review` shows the design working
as intended: its homepage was challenge-blocked, so only the domain name
scored, and the audit CSV records `homepage behind bot protection` as the
reason. Less evidence means a lower bucket, not a confident guess.

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
