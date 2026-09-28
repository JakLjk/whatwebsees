from django.test import SimpleTestCase
from django.urls import reverse


class AboutAndAuthorshipTests(SimpleTestCase):
    def test_about_is_substantive_indexable_and_in_sitemap(self):
        response = self.client.get(reverse("about"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.count(b"<h1"), 1)
        self.assertContains(response, "independently developed public project")
        self.assertContains(response, "Privacy-first by design")
        self.assertContains(response, "processed by the WhatWebSees server")
        self.assertContains(response, "locally maintained copy of the DB-IP City Lite")
        self.assertContains(
            response,
            '<link rel="canonical" href="https://whatwebsees.com/about/">',
        )
        self.assertNotIn("X-Robots-Tag", response.headers)

        sitemap = self.client.get(reverse("sitemap"))
        self.assertContains(sitemap, "<loc>https://whatwebsees.com/about/</loc>")

    def test_project_links_are_visible_on_about_and_footers(self):
        expected = (
            ("https://github.com/JakLjk/whatwebsees", "Source code on GitHub"),
            ("https://www.linkedin.com/in/jakub-lejk/", "Jakub Lejk on LinkedIn"),
        )
        about = self.client.get(reverse("about"))
        for url, label in expected:
            self.assertContains(about, f'href="{url}"')
            self.assertContains(about, label)

        for route in ("home", "dns-lookup"):
            with self.subTest(route=route):
                response = self.client.get(reverse(route))
                self.assertContains(response, 'href="/about/"')
                for url, _ in expected:
                    self.assertContains(response, f'href="{url}"')

    def test_learning_articles_show_real_authorship_and_matching_schema(self):
        response = self.client.get("/learn/how-ip-geolocation-works/")

        self.assertContains(response, 'by <a href="/about/">Jakub Lejk</a>')
        self.assertContains(response, '"@type": "Person"')
        self.assertContains(response, '"name": "Jakub Lejk"')
        self.assertContains(response, '"url": "https://whatwebsees.com/about/"')


class PriorityPageAuthorityTests(SimpleTestCase):
    priority_routes = (
        "ip-lookup",
        "download-time-calculator",
        "user-agent",
        "redirect-checker",
        "screen-resolution",
        "dns-lookup",
    )

    def test_priority_pages_use_reusable_source_block(self):
        for route in self.priority_routes:
            with self.subTest(route=route):
                response = self.client.get(reverse(route))
                self.assertContains(response, "Sources &amp; further reading")
                self.assertContains(response, 'class="source-list"')
                self.assertNotContains(response, "nofollow")

    def test_dbip_attribution_is_visible_where_results_are_used(self):
        home = self.client.get(reverse("home"))
        lookup = self.client.get(reverse("ip-lookup"))

        for response in (home, lookup):
            self.assertContains(response, 'href="https://db-ip.com/')
            self.assertContains(response, "IP Geolocation by DB-IP")

        self.assertContains(lookup, "locally maintained DB-IP City Lite dataset")
        self.assertContains(lookup, "does not supply this tool's ASN, ISP or organization")
        self.assertNotContains(lookup, "location.timezone")

    def test_priority_pages_have_requested_interpretive_sections(self):
        expected = {
            "ip-lookup": (
                "How to interpret your result",
                "ISP, ASN and organization are different",
                "IPv4 and IPv6 caveats",
            ),
            "download-time-calculator": (
                "Mbps, MB/s and file-size units",
                "Ideal download-time reference",
                "How to get a more reliable speed-test result",
            ),
            "user-agent": (
                "Why so many strings start with Mozilla/5.0",
                "User-Agent reduction and Client Hints",
                "test features, not browser names",
            ),
            "redirect-checker": (
                "Permanent or temporary",
                "The Location header and each hop",
                "When method preservation matters",
            ),
            "screen-resolution": (
                "screen resolution is not the same as browser viewport size",
                "Estimated physical-pixel dimensions",
                "Browser zoom and orientation",
            ),
            "dns-lookup": (
                "Plain-language DNS record guide",
                "DNS lookup is not a website availability test",
                "Authoritative servers and recursive resolvers",
            ),
        }
        for route, markers in expected.items():
            with self.subTest(route=route):
                response = self.client.get(reverse(route))
                for marker in markers:
                    self.assertContains(response, marker)

    def test_contextual_links_cover_each_priority_cluster(self):
        expectations = {
            "ip-lookup": (
                "/ip-address-checker/", "/reverse-dns/", "/dns-lookup/", "/subnet-calculator/",
            ),
            "download-time-calculator": (
                "/website-status/", "/dns-lookup/", "/browser-check/", "/glossary/",
            ),
            "user-agent": (
                "/browser-check/", "/privacy-check/", "/http-headers/", "/canvas-fingerprint/", "/webgl/",
            ),
            "redirect-checker": (
                "/website-status/", "/server-headers/", "/security-headers/", "/ssl-checker/", "/meta-tags-checker/",
            ),
            "screen-resolution": (
                "/browser-check/", "/user-agent/", "/webgl/", "/privacy-check/",
            ),
            "dns-lookup": (
                "/dnssec-checker/", "/email-dns-checker/", "/hostname-lookup/", "/reverse-dns/", "/website-status/",
            ),
        }
        for route, paths in expectations.items():
            with self.subTest(route=route):
                response = self.client.get(reverse(route))
                for path in paths:
                    self.assertContains(response, f'href="{path}"')
