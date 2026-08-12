#!/usr/bin/env python3
"""Offline tests for the pure logic: no network required.

    python3 test_umscan.py
"""

import unittest

from umscan.affiliation import AFFILIATED, REVIEW, UNRELATED, Evidence, assess
from umscan.extract import Page, clean_email
from umscan.profile import Profiler
from umscan.urls import (
    EXTERNAL, INTERNAL, NOISE, classify, has_skippable_extension,
    host_of, is_internal_host, normalize_url, registrable_domain,
)
from umscan.render import (
    HybridFetcher, PlaywrightFetcher, RENDER_UNAVAILABLE, _looks_like_js_shell,
    _worth_rendering,
)
from umscan import report
from umscan.crawl import DomainHit
from umscan.fetch import CHALLENGED, ERROR, OK, Fetcher, Response
from umscan.profile import _failed
from umscan.whois import _parse, _referral_server


class TestUrls(unittest.TestCase):
    def test_normalize_resolves_and_strips_fragments(self):
        self.assertEqual(
            normalize_url("/news?a=1#top", "https://lsa.umich.edu/dept/"),
            "https://lsa.umich.edu/news?a=1",
        )

    def test_normalize_rejects_non_http_schemes(self):
        for bad in ("mailto:a@b.com", "javascript:void(0)", "tel:+1", "#anchor", ""):
            self.assertIsNone(normalize_url(bad))

    def test_normalize_drops_default_port_keeps_odd_one(self):
        self.assertEqual(normalize_url("https://x.umich.edu:443/a"), "https://x.umich.edu/a")
        self.assertEqual(normalize_url("https://x.umich.edu:8443/a"), "https://x.umich.edu:8443/a")

    def test_registrable_domain(self):
        cases = {
            "www.lsa.umich.edu": "umich.edu",
            "michigandaily.com": "michigandaily.com",
            "www.bbc.co.uk": "bbc.co.uk",
            "a.b.example.com.au": "example.com.au",
        }
        for host, want in cases.items():
            self.assertEqual(registrable_domain(host), want, host)

    def test_internal_matching_is_suffix_safe(self):
        self.assertTrue(is_internal_host("lsa.umich.edu"))
        self.assertTrue(is_internal_host("umich.edu"))
        # A lookalike domain must never count as internal.
        self.assertFalse(is_internal_host("notumich.edu"))
        self.assertFalse(is_internal_host("umich.edu.evil.com"))

    def test_classify_buckets(self):
        self.assertEqual(classify("https://lsa.umich.edu/a"), (INTERNAL, "lsa.umich.edu"))
        self.assertEqual(classify("https://www.michigandaily.com/a"),
                         (EXTERNAL, "michigandaily.com"))
        self.assertEqual(classify("https://docs.google.com/a")[0], NOISE)
        # Every non-UM .edu is noise.
        self.assertEqual(classify("https://www.msu.edu/")[0], NOISE)

    def test_malformed_urls_return_none_instead_of_raising(self):
        """Regression: a bracketed authority used to abort the whole crawl."""
        for bad in ("http://[openid_connect_generic_auth_url]/x",
                    "//[not-an-ip]/y",
                    "http://[]/z"):
            self.assertIsNone(normalize_url(bad, "https://x.umich.edu/"), bad)

    def test_host_of_tolerates_malformed_url(self):
        self.assertEqual(host_of("http://[bad]/x"), "")

    def test_skippable_extensions(self):
        self.assertTrue(has_skippable_extension("https://x.umich.edu/report.pdf"))
        self.assertFalse(has_skippable_extension("https://x.umich.edu/report"))


class TestExtract(unittest.TestCase):
    HTML = """<html><head><title>T</title></head><body>
      <a href="/a">a</a><a href="https://umich.edu/b">b</a>
      <a href="mailto:Help@UMICH.edu?subject=x">m</a>
      <script>var x="junk@tracker.io";</script>
      <p>write to info at michiganradio dot org, not logo@2x.png</p>
      <p>or dept [at] umich [dot] edu</p></body></html>"""

    def test_links_exclude_mailto(self):
        page = Page(self.HTML)
        self.assertEqual(page.links, ["/a", "https://umich.edu/b"])

    def test_emails_found_and_deobfuscated(self):
        emails = Page(self.HTML).emails()
        self.assertIn("help@umich.edu", emails)
        self.assertIn("info@michiganradio.org", emails)
        self.assertIn("dept@umich.edu", emails)

    def test_script_contents_are_ignored(self):
        self.assertNotIn("junk@tracker.io", Page(self.HTML).emails())

    def test_clean_email_rejects_lookalikes(self):
        for bad in ("logo@2x.png", "a@example.com", "user@domain.com", "no-at-sign"):
            self.assertEqual(clean_email(bad), "")
        self.assertEqual(clean_email(" Good.Name@Umich.EDU "), "good.name@umich.edu")

    def test_contact_ranking_prefers_umich(self):
        best = Profiler._best_contacts(
            ["webmaster@vendor.com", "office@ums.org", "umstix@umich.edu"], "ums.org")
        self.assertTrue(best.startswith("umstix@umich.edu"))


class TestAffiliation(unittest.TestCase):
    def test_regents_whois_is_decisive(self):
        a = assess(Evidence("umgolfcourse.com",
                            whois_org="Regents of the University of Michigan"))
        self.assertEqual(a.label, AFFILIATED)

    def test_um_nameservers_survive_privacy_redaction(self):
        # michiganradio.org: registrant hidden, but UM runs its DNS.
        a = assess(Evidence("michiganradio.org",
                            nameservers=["cffw1.dns.umich.com"],
                            page_text="A service of the University of Michigan, Ann Arbor, MI",
                            links_to_umich=True))
        self.assertEqual(a.label, AFFILIATED)

    def test_unrelated_domain_scores_zero(self):
        a = assess(Evidence("nytimes.com", page_text="Breaking news today"))
        self.assertEqual(a.label, UNRELATED)
        self.assertEqual(a.score, 0)

    def test_other_michigan_institution_is_not_um(self):
        a = assess(Evidence("michiganstate.com",
                            whois_org="Michigan State University",
                            page_text="Michigan State University Spartans"))
        self.assertEqual(a.label, UNRELATED)

    def test_michigan_in_name_alone_is_not_enough(self):
        a = assess(Evidence("michigan.gov", page_text="State of Michigan services"))
        self.assertEqual(a.label, UNRELATED)

    def test_ambiguous_case_goes_to_review(self):
        # A UM person registered it, but nothing else corroborates.
        a = assess(Evidence("somejournal.us", whois_emails=["prof@umich.edu"]))
        self.assertEqual(a.label, REVIEW)

    def test_um_health_domains_are_recognised(self):
        # Real UM Health properties that scored only 4-5 before tuning.
        a = assess(Evidence("uofmhealth.org",
                            page_text="University of Michigan Health. "
                                      "University of Michigan. University of Michigan.",
                            links_to_umich=True))
        self.assertEqual(a.label, AFFILIATED)
        b = assess(Evidence("myuofmhealth.org", nameservers=["ns1.umich.edu"]))
        self.assertEqual(b.label, AFFILIATED)

    def test_specific_token_beats_generic_one(self):
        a = assess(Evidence("michiganmedicine.org"))
        self.assertIn("domain-token-michiganmedicine", a.reason)
        self.assertNotIn("domain-token-michigan(", a.reason)

    def test_signals_are_reported(self):
        a = assess(Evidence("x.org", nameservers=["ns1.umich.edu"]))
        self.assertIn("nameserver-umich", a.reason)


class TestWhoisParsing(unittest.TestCase):
    EDUCAUSE = """Domain Name: UMICH.EDU

Registrant:
\tUniversity of Michigan -- ITD
\tAnn Arbor, MI 48105
\tUSA

Administrative Contact:
\tDomain Admin
\tdomainreg@umich.edu

Name Servers:
\tDNS1.ITD.UMICH.EDU
\tDNS2.ITD.UMICH.EDU
"""

    THIN_REDACTED = """Domain Name: example.org
Registrar WHOIS Server: whois.tucows.com
Registrar: Tucows Domains Inc.
Registrar Abuse Contact Email: domainabuse@tucows.com
Registrant Organization: REDACTED FOR PRIVACY
Name Server: cffw1.dns.umich.com
"""

    def test_educause_block_format(self):
        r = _parse("umich.edu", self.EDUCAUSE, "whois.educause.edu")
        self.assertTrue(r.ok)
        self.assertEqual(r.org, "University of Michigan -- ITD")
        self.assertIn("domainreg@umich.edu", r.emails)
        self.assertIn("dns1.itd.umich.edu", r.nameservers)

    def test_redacted_record_does_not_pass_off_abuse_mailbox(self):
        r = _parse("example.org", self.THIN_REDACTED, "whois.pir.org")
        self.assertTrue(r.redacted)
        self.assertEqual(r.real_emails, [])
        # The column is an address, so a registrar abuse mailbox is not an answer.
        self.assertEqual(r.contact(), "redacted")

    def test_technical_contact_is_preferred(self):
        record = """Domain Name: example.com
Registrant Email: owner@example.com
Admin Email: admin@example.com
Tech Email: hostmaster@example.com
Registrar Abuse Contact Email: abuse@registrar.com
"""
        r = _parse("example.com", record, "whois.verisign-grs.com")
        self.assertEqual(r.contact(), "hostmaster@example.com")
        self.assertEqual(r.contact_role, "tech")

    def test_falls_back_to_admin_then_registrant(self):
        no_tech = """Domain Name: example.com
Registrant Email: owner@example.com
Admin Email: admin@example.com
"""
        r = _parse("example.com", no_tech, "whois.verisign-grs.com")
        self.assertEqual(r.contact(), "admin@example.com")
        self.assertEqual(r.contact_role, "admin")

        only_owner = "Domain Name: example.com\nRegistrant Email: owner@example.com\n"
        r2 = _parse("example.com", only_owner, "whois.verisign-grs.com")
        self.assertEqual(r2.contact(), "owner@example.com")
        self.assertEqual(r2.contact_role, "registrant")

    def test_proxy_tech_address_is_rejected(self):
        proxied = """Domain Name: example.com
Tech Email: %s@example.com.whoisproxy.org
Registrar: Amazon Registrar, Inc.
Registrant Organization: c/o whoisproxy.com
""" % ("a1b2c3d4" * 8)
        r = _parse("example.com", proxied, "whois.verisign-grs.com")
        self.assertEqual(r.contact(), "redacted")

    def test_educause_technical_block_wins(self):
        r = _parse("umich.edu", self.EDUCAUSE, "whois.educause.edu")
        self.assertEqual(r.contact(), "domainreg@umich.edu")
        self.assertIn(r.contact_role, ("tech", "admin"))

    def test_registry_refusal_is_flagged(self):
        r = _parse("myumi.ch", "Requests of this client are not permitted.", "whois.nic.ch")
        self.assertFalse(r.ok)
        self.assertIn("refuses", r.error)

    def test_no_match_is_flagged(self):
        r = _parse("nope.com", "No match for domain NOPE.COM", "whois.verisign-grs.com")
        self.assertFalse(r.ok)

    def test_referral_extraction(self):
        self.assertEqual(_referral_server("Registrar WHOIS Server: whois.tucows.com"),
                         "whois.tucows.com")


class _ConsumedResponse:
    """A streamed response whose body has already been read."""

    encoding = None
    headers: dict = {}

    @property
    def apparent_encoding(self):
        raise RuntimeError("The content for this response was already consumed")

    @property
    def content(self):
        raise RuntimeError("The content for this response was already consumed")


class TestDecoding(unittest.TestCase):
    """Regression: decoding must never reach for requests' apparent_encoding."""

    def test_decode_does_not_touch_consumed_body(self):
        text = Fetcher._decode(_ConsumedResponse(), b"<html>hi</html>")
        self.assertEqual(text, "<html>hi</html>")

    def test_decode_sniffs_declared_charset(self):
        body = b'<meta charset="iso-8859-1"><p>caf\xe9</p>'
        self.assertIn("caf\u00e9", Fetcher._decode(_ConsumedResponse(), body))

    def test_decode_survives_bogus_charset(self):
        body = b'<meta charset="not-a-real-codec"><p>ok</p>'
        self.assertIn("ok", Fetcher._decode(_ConsumedResponse(), body))


class TestProfileFailure(unittest.TestCase):
    def test_failed_external_goes_to_review_not_unrelated(self):
        hit = DomainHit("x.org", EXTERNAL, "https://umich.edu/", "https://x.org/")
        row = _failed(hit, RuntimeError("boom"))
        self.assertEqual(row.type, "external-review")
        self.assertEqual(row.domain, "x.org")
        self.assertEqual(row.source_url, "https://umich.edu/")
        self.assertIn("boom", row.reason)

    def test_failed_internal_stays_internal(self):
        hit = DomainHit("a.umich.edu", INTERNAL, "seed", "https://a.umich.edu/")
        self.assertEqual(_failed(hit, ValueError("x")).type, INTERNAL)


class _StubFetcher:
    """Stands in for the requests-backed fetcher."""

    def __init__(self, response):
        self.response = response
        self.calls = 0

    def get(self, url, retries=1):
        self.calls += 1
        return self.response

    def close(self):
        pass


class TestCrawlFaultIsolation(unittest.TestCase):
    def test_fetch_exception_becomes_an_error_response(self):
        from umscan.config import Settings
        from umscan.crawl import Crawler

        class _Exploding:
            def get(self, url, retries=1):
                raise RuntimeError("socket exploded")

        crawler = Crawler(Settings(), _Exploding())
        resp = crawler._safe_fetch("https://x.umich.edu/")
        self.assertFalse(resp.usable)
        self.assertIn("socket exploded", resp.note)


class TestPageBudget(unittest.TestCase):
    def test_zero_means_unlimited(self):
        from umscan.config import Settings
        from umscan.crawl import Crawler

        crawler = Crawler(Settings(max_pages=0), fetcher=None)
        crawler.result.pages_fetched = 10_000
        self.assertFalse(crawler._page_budget_spent())

    def test_positive_budget_is_enforced(self):
        from umscan.config import Settings
        from umscan.crawl import Crawler

        crawler = Crawler(Settings(max_pages=50), fetcher=None)
        crawler.result.pages_fetched = 49
        self.assertFalse(crawler._page_budget_spent())
        crawler.result.pages_fetched = 50
        self.assertTrue(crawler._page_budget_spent())


class TestReportColumns(unittest.TestCase):
    def test_csv_has_four_columns_without_source_url(self):
        self.assertEqual(report.COLUMNS,
                         ["domain", "type", "whois_contact", "on_page_contact"])

    def test_audit_csv_still_records_provenance(self):
        for column in ("source_url", "whois_role", "signals"):
            self.assertIn(column, report.EVIDENCE_COLUMNS)


class TestRenderPolicy(unittest.TestCase):
    LINK_RICH = "<html><body>" + "<a href='/x'>x</a>" * 5 + "</body></html>"
    JS_SHELL = "<html><body><div id='root'></div><script src='/app.js'></script></body></html>"

    def test_challenge_escalates(self):
        self.assertTrue(_worth_rendering(Response("u", CHALLENGED, 403)))

    def test_normal_page_does_not_escalate(self):
        self.assertFalse(_worth_rendering(Response("u", OK, 200, text=self.LINK_RICH)))

    def test_js_shell_escalates(self):
        self.assertTrue(_worth_rendering(Response("u", OK, 200, text=self.JS_SHELL)))

    def test_hard_failure_does_not_escalate(self):
        # A dead host will not become alive in a browser.
        self.assertFalse(_worth_rendering(Response("u", ERROR, 0)))

    def test_js_shell_detection(self):
        self.assertTrue(_looks_like_js_shell(self.JS_SHELL))
        self.assertFalse(_looks_like_js_shell(self.LINK_RICH))

    def test_unstarted_renderer_reports_unavailable(self):
        r = PlaywrightFetcher()
        r.error = "playwright not installed"
        self.assertEqual(r.get("https://x.umich.edu/").status, RENDER_UNAVAILABLE)

    def test_hybrid_without_renderer_passes_through(self):
        plain = _StubFetcher(Response("u", CHALLENGED, 403))
        h = HybridFetcher(plain, None)
        self.assertFalse(h.enabled)
        self.assertEqual(h.get("https://x.umich.edu/").status, CHALLENGED)
        self.assertEqual(plain.calls, 1)

    def test_hybrid_renders_only_once_per_url(self):
        plain = _StubFetcher(Response("u", CHALLENGED, 403))
        rendered = Response("u", OK, 200, text="<html><a href='/a'>a</a></html>")

        class _StubRenderer:
            error = ""
            live = 1
            def __init__(self): self.calls = 0
            def get(self, url, retries=0):
                self.calls += 1
                return rendered
            def close(self): pass

        renderer = _StubRenderer()
        h = HybridFetcher(plain, renderer)
        self.assertTrue(h.get("https://x.umich.edu/").usable)
        h.get("https://x.umich.edu/")          # same URL again
        self.assertEqual(renderer.calls, 1)
        self.assertEqual(h.stats()["succeeded"], 1)

    def test_rendering_can_be_switched_off_between_phases(self):
        """--render-crawl-only flips this after the crawl; no domain is dropped."""
        plain = _StubFetcher(Response("u", CHALLENGED, 403))

        class _StubRenderer:
            error = ""
            live = 1
            def __init__(self): self.calls = 0
            def get(self, url, retries=0):
                self.calls += 1
                return Response(url, OK, 200, text="<html><a href='/a'>a</a></html>")
            def close(self): pass

        renderer = _StubRenderer()
        h = HybridFetcher(plain, renderer)
        h.get("https://a.umich.edu/")
        self.assertEqual(renderer.calls, 1)

        h.rendering_enabled = False
        self.assertFalse(h.enabled)
        result = h.get("https://b.umich.edu/")
        self.assertEqual(renderer.calls, 1)          # no further renders
        self.assertEqual(result.status, CHALLENGED)  # still returns a usable row

    def test_dead_pool_reports_unavailable(self):
        r = PlaywrightFetcher(workers=2)
        self.assertEqual(r.live, 0)
        self.assertEqual(r.get("https://x.umich.edu/").status, RENDER_UNAVAILABLE)

    def test_hybrid_keeps_original_verdict_when_render_fails(self):
        plain = _StubFetcher(Response("u", CHALLENGED, 403, note="interstitial"))

        class _StubRenderer:
            error = ""
            live = 1
            def get(self, url, retries=0):
                return Response(url, CHALLENGED, 403, note="challenge did not clear")
            def close(self): pass

        h = HybridFetcher(plain, _StubRenderer())
        result = h.get("https://x.umich.edu/")
        self.assertEqual(result.status, CHALLENGED)
        self.assertEqual(h.stats()["still_blocked"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
