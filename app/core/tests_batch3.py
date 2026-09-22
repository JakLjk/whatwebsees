import json
from unittest.mock import Mock, patch

import dns.rdatatype
from django.test import SimpleTestCase
from django.urls import reverse

from core.batch3_utils import (
    approximate_age,
    inspect_dnssec,
    inspect_email_dns,
    parse_meta_tags,
    parse_robots,
    parse_sitemap,
    rdap_lookup,
)
from core.content_catalog import ARTICLES
from core.network_utils import HTTPHop, HTTPResult, NetworkToolError, _request_once, safe_http_request


class BatchThreePublicPageTests(SimpleTestCase):
    pages = (
        ("dnssec-checker", "DNSSEC Checker", "/dnssec-checker/"),
        ("email-dns-checker", "Email DNS Checker", "/email-dns-checker/"),
        ("redirect-checker", "Redirect Checker", "/redirect-checker/"),
        ("security-headers", "HTTP Security Headers Checker", "/security-headers/"),
        ("robots-txt-checker", "Robots.txt Checker", "/robots-txt-checker/"),
        ("sitemap-checker", "XML Sitemap Checker", "/sitemap-checker/"),
        ("meta-tags-checker", "Meta Tag Checker", "/meta-tags-checker/"),
        ("url-parser", "URL Parser &amp; Analyzer", "/url-parser/"),
        ("file-hash", "File Hash Calculator", "/file-hash/"),
        ("rdap-lookup", "Domain RDAP Lookup", "/rdap-lookup/"),
        ("domain-age", "Domain Age Checker", "/domain-age/"),
    )

    def test_new_tools_are_complete_indexable_pages(self):
        titles = set()
        for route, heading, path in self.pages:
            with self.subTest(route=route):
                response = self.client.get(reverse(route))
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, f'<h1 id="page-title">{heading}</h1>')
                self.assertContains(response, '<meta name="description"')
                self.assertContains(response, f'rel="canonical" href="https://whatwebsees.com{path}"')
                self.assertContains(response, 'property="og:title"')
                self.assertContains(response, 'name="twitter:title"')
                title = response.context["title"]
                self.assertNotIn(title, titles)
                titles.add(title)

    def test_new_tools_are_linked_from_hub_and_sitemap(self):
        hub = self.client.get(reverse("tools"))
        sitemap = self.client.get(reverse("sitemap"))
        for _, _, path in self.pages:
            self.assertContains(hub, f'href="{path}"')
            self.assertContains(sitemap, f"<loc>https://whatwebsees.com{path}</loc>")

    def test_network_post_results_are_private_and_not_cached(self):
        with patch("core.views.inspect_dnssec", return_value={
            "domain": "example.com", "dnskeys": (), "ds_records": (),
            "has_dnskey": False, "has_ds": False, "interpretation": "No records.",
        }):
            response = self.client.post(reverse("dnssec-checker"), {"domain": "example.com"})
        self.assertIn("private", response.headers["Cache-Control"])
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_local_tools_do_not_submit_or_fetch(self):
        url_html = self.client.get(reverse("url-parser")).content.decode()
        hash_html = self.client.get(reverse("file-hash")).content.decode()
        self.assertNotIn("<form", url_html)
        self.assertNotIn("fetch(", url_html)
        self.assertIn("new URL", url_html)
        self.assertNotIn("<form", hash_html)
        self.assertNotIn("fetch(", hash_html)
        self.assertIn("crypto.subtle.digest", hash_html)
        self.assertIn("512 * 1024 * 1024".replace(" ", ""), hash_html.replace(" ", ""))

    def test_every_existing_individual_tool_has_specific_result_guidance(self):
        from core.views import RESULT_GUIDANCE, TOOL_PAGE_METADATA

        for key, guidance in RESULT_GUIDANCE.items():
            with self.subTest(tool=key):
                response = self.client.get(TOOL_PAGE_METADATA[key]["path"])
                self.assertContains(response, "What this result means")
                self.assertContains(response, guidance)


class LearnPageTests(SimpleTestCase):
    def test_learn_hub_and_glossary(self):
        hub = self.client.get(reverse("learn"))
        glossary = self.client.get(reverse("glossary"))
        self.assertEqual(hub.status_code, 200)
        self.assertContains(hub, '<h1 id="page-title">Learn How the Web Works</h1>')
        self.assertEqual(glossary.status_code, 200)
        self.assertContains(glossary, '<h1 id="page-title">Web, Network &amp; Privacy Glossary</h1>')
        self.assertGreaterEqual(glossary.content.count(b"<dt>"), 40)
        self.assertContains(glossary, 'href="/rdap-lookup/"')

    def test_every_article_has_metadata_schema_and_tool_links(self):
        sitemap = self.client.get(reverse("sitemap"))
        hub = self.client.get(reverse("learn"))
        for slug, metadata in ARTICLES.items():
            with self.subTest(slug=slug):
                path = f"/learn/{slug}/"
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, f'<h1 id="page-title">{metadata["heading"]}</h1>')
                self.assertContains(response, f'rel="canonical" href="https://whatwebsees.com{path}"')
                self.assertContains(response, 'property="og:type" content="article"')
                self.assertContains(response, '"@type": "Article"')
                self.assertContains(response, '"datePublished": "2026-09-21"')
                self.assertContains(response, '"@type": "BreadcrumbList"')
                for tool in response.context["article_tools"]:
                    self.assertContains(response, f'href="{tool["path"]}"')
                self.assertContains(sitemap, f"<loc>https://whatwebsees.com{path}</loc>")
                self.assertContains(hub, f'href="{path}"')

    def test_articles_are_substantial(self):
        for slug in ARTICLES:
            response = self.client.get(f"/learn/{slug}/")
            words = response.content.decode().split()
            self.assertGreater(len(words), 600, slug)

    def test_navigation_links_learn_and_glossary(self):
        response = self.client.get(reverse("home"))
        self.assertContains(response, 'href="/learn/"')
        self.assertContains(response, 'href="/glossary/"')


class DNSDiagnosticTests(SimpleTestCase):
    def _answer(self, records):
        answer = list(records)
        answer.rrset = True
        return answer

    @patch("core.batch3_utils.dns.dnssec.key_id", return_value=12345)
    @patch("core.batch3_utils._answer")
    def test_dnssec_interpretation_is_cautious(self, query, key_id):
        key = Mock(flags=257, algorithm=13)
        key.to_text.return_value = "257 3 13 abc"
        dnskey = Mock(rrset=True)
        dnskey.__iter__ = Mock(return_value=iter((key,)))
        ds = Mock(rrset=True)
        ds.__iter__ = Mock(return_value=iter((Mock(to_text=Mock(return_value="12345 13 2 digest")),)))
        query.side_effect = (dnskey, ds)
        result = inspect_dnssec("Example.COM")
        self.assertTrue(result["has_dnskey"])
        self.assertTrue(result["has_ds"])
        self.assertIn("not a full cryptographic", result["interpretation"])

    @patch("core.batch3_utils._txt_records")
    @patch("core.batch3_utils._answer")
    def test_email_records_and_dmarc_policy(self, answer, txt):
        mx_item = Mock()
        mx_item.to_text.return_value = "10 mail.example.com."
        mx = Mock(rrset=True)
        mx.__iter__ = Mock(return_value=iter((mx_item,)))
        answer.return_value = mx
        txt.side_effect = (
            ("v=spf1 -all", "unrelated=value"),
            ("v=DMARC1; p=quarantine; rua=mailto:reports@example.com",),
            ("v=DKIM1; p=abc",),
        )
        result = inspect_email_dns("example.com", "selector1")
        self.assertEqual(result["spf_records"], ("v=spf1 -all",))
        self.assertEqual(result["dmarc_policy"], "quarantine")
        self.assertTrue(result["dkim_records"])

    def test_invalid_dkim_selector_is_rejected(self):
        with self.assertRaises(NetworkToolError):
            inspect_email_dns("example.com", "bad.selector")


class ParserTests(SimpleTestCase):
    def test_robots_parser_detects_directives(self):
        sitemaps, agents = parse_robots("User-agent: *\nDisallow: /private\nSitemap: https://example.com/map.xml\n")
        self.assertEqual(agents, ("*",))
        self.assertEqual(sitemaps, ("https://example.com/map.xml",))

    def test_urlset_and_sitemapindex_are_bounded_to_samples(self):
        urls = "".join(f"<url><loc>https://example.com/{i}</loc><lastmod>2026-01-01</lastmod></url>" for i in range(30))
        parsed = parse_sitemap(f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>')
        self.assertEqual(parsed["type"], "urlset")
        self.assertEqual(parsed["count"], 30)
        self.assertEqual(len(parsed["samples"]), 25)
        index = parse_sitemap("<sitemapindex><sitemap><loc>https://example.com/a.xml</loc></sitemap></sitemapindex>")
        self.assertEqual(index["type"], "sitemapindex")

    def test_malformed_and_entity_xml_are_rejected(self):
        for value in ("<urlset><url>", '<!DOCTYPE x [<!ENTITY y "z">]><urlset/>'):
            with self.subTest(value=value), self.assertRaises(NetworkToolError):
                parse_sitemap(value)

    def test_meta_parser_extracts_first_server_html_values(self):
        values = parse_meta_tags('''<html><head><title> Example </title><meta name="description" content="Summary"><meta property="og:title" content="Social"><link rel="canonical" href="https://example.com/"></head></html>''')
        self.assertEqual(values["title"], "Example")
        self.assertEqual(values["description"], "Summary")
        self.assertEqual(values["og_title"], "Social")
        self.assertEqual(values["canonical"], "https://example.com/")


class HTTPNetworkExtensionTests(SimpleTestCase):
    @patch("core.network_utils._request_once")
    def test_redirect_chain_records_each_hop(self, once):
        once.side_effect = (
            (301, "Moved", {"location": "https://www.example.com/"}, b""),
            (200, "OK", {"content-type": "text/html"}, b""),
        )
        result = safe_http_request("https://example.com/")
        self.assertEqual(result.redirects, 1)
        self.assertEqual(len(result.chain), 2)
        self.assertEqual(result.chain[0].location, "https://www.example.com/")
        self.assertEqual(result.url, "https://www.example.com/")

    @patch("core.network_utils._make_connection")
    @patch("core.network_utils.resolve_public_host")
    def test_body_limit_is_enforced(self, resolve, make_connection):
        resolve.return_value = Mock(addresses=("8.8.8.8",))
        response = Mock(status=200, reason="OK")
        response.getheaders.return_value = [("Content-Type", "text/plain")]
        response.read.return_value = b"x" * 11
        make_connection.return_value.getresponse.return_value = response
        with self.assertRaises(NetworkToolError) as raised:
            _request_once("https://example.com/", "GET", None, body_limit=10)
        self.assertEqual(raised.exception.code, "response_too_large")
        make_connection.return_value.close.assert_called()

    @patch("core.views.safe_http_request")
    def test_security_headers_present_and_missing(self, request):
        request.return_value = HTTPResult("https://example.com/", 200, "OK", 10, 0, {"strict-transport-security": "max-age=100"})
        response = self.client.post(reverse("security-headers"), {"url": "example.com"})
        self.assertContains(response, "max-age=100")
        self.assertContains(response, "Not observed")
        self.assertNotContains(response, "Grade")

    @patch("core.views.safe_http_request")
    def test_robots_view_uses_forced_origin_path(self, request):
        request.return_value = HTTPResult("https://example.com/robots.txt", 200, "OK", 10, 0, {"content-type": "text/plain"}, b"User-agent: *\nSitemap: https://example.com/s.xml\n")
        response = self.client.post(reverse("robots-txt-checker"), {"url": "https://example.com/arbitrary/path"})
        request.assert_called_once_with("https://example.com/robots.txt", fetch_body=True, max_body=64 * 1024)
        self.assertContains(response, "https://example.com/s.xml")

    @patch("core.views.safe_http_request")
    def test_sitemap_and_meta_views_parse_bounded_bodies(self, request):
        request.return_value = HTTPResult("https://example.com/sitemap.xml", 200, "OK", 10, 0, {"content-type": "application/xml"}, b"<urlset><url><loc>https://example.com/a</loc></url></urlset>")
        sitemap = self.client.post(reverse("sitemap-checker"), {"url": "example.com"})
        self.assertContains(sitemap, "urlset")
        self.assertContains(sitemap, "https://example.com/a")
        request.return_value = HTTPResult("https://example.com/", 200, "OK", 10, 0, {"content-type": "text/html"}, b"<title>Hello</title><meta name='robots' content='noindex'>")
        meta = self.client.post(reverse("meta-tags-checker"), {"url": "example.com"})
        self.assertContains(meta, "Hello")
        self.assertContains(meta, "noindex")


class RDAPTests(SimpleTestCase):
    @patch("core.batch3_utils.safe_http_request")
    @patch("core.batch3_utils.rdap_bootstrap")
    def test_rdap_uses_bootstrapped_https_service_and_limits_fields(self, bootstrap, request):
        bootstrap.return_value = [[["com"], ["https://rdap.example/"]]]
        payload = {
            "ldhName": "EXAMPLE.COM", "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]], "privateSecret": "must-not-render"}],
        }
        request.return_value = HTTPResult("https://rdap.example/domain/example.com", 200, "OK", 20, 0, {"content-type": "application/rdap+json"}, json.dumps(payload).encode())
        result = rdap_lookup("example.com")
        self.assertEqual(result["registrar"], "Example Registrar")
        self.assertEqual(result["nameservers"], ("ns1.example.com",))
        request.assert_called_once_with("https://rdap.example/domain/example.com", fetch_body=True, max_body=768 * 1024)
        self.assertNotIn("privateSecret", result)

    def test_domain_age_is_approximate_and_nonnegative(self):
        age = approximate_age("2000-01-01T00:00:00Z")
        self.assertGreater(age["years"], 20)
        self.assertGreater(age["total_days"], 9000)


class NginxRateLimitTests(SimpleTestCase):
    def test_every_new_network_post_route_is_rate_limited(self):
        config_path = (
            __import__("pathlib").Path(__file__).resolve().parents[2]
            / "nginx"
            / "default.conf"
        )

        if not config_path.is_file():
            self.skipTest(
                "nginx/default.conf is not included in the Django web image; "
                "deployment nginx configuration is validated separately."
            )

        config = config_path.read_text()
        for route in (
            "dnssec-checker", "email-dns-checker", "redirect-checker", "security-headers",
            "robots-txt-checker", "sitemap-checker", "meta-tags-checker", "rdap-lookup", "domain-age",
        ):
            self.assertIn(route, config)
        self.assertNotIn("url-parser|file-hash", config)

class FaviconTests(SimpleTestCase):
    def test_png_favicon(self):
        response = self.client.get(reverse("favicon-png"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/png")
        self.assertGreater(len(response.content), 100)

    def test_home_references_png_favicon(self):
        response = self.client.get(reverse("home"))

        self.assertContains(
            response,
            '<link rel="icon" href="/favicon.png" '
            'type="image/png" sizes="192x192">'
        )
