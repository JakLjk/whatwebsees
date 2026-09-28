import json
from datetime import datetime, timezone
from pathlib import Path
from unittest import SkipTest
from unittest.mock import Mock, patch

from django.test import Client, SimpleTestCase
from django.urls import reverse

from core.network_utils import HTTPHop, HTTPResult, NetworkToolError, TLSResult


def http_result(**overrides):
    values = {
        "url": "https://example.com/",
        "status": 200,
        "reason": "OK",
        "elapsed_ms": 24,
        "redirects": 0,
        "headers": {"content-type": "text/html"},
        "chain": (
            HTTPHop("https://example.com/", 200, "OK", None, 24),
        ),
    }
    values.update(overrides)
    return HTTPResult(**values)


class APITestMixin:
    def post_json(self, route_name, payload, **extra):
        return self.client.post(
            reverse(route_name),
            data=json.dumps(payload),
            content_type="application/json",
            **extra,
        )

    def assert_api_headers(self, response):
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["X-Robots-Tag"], "noindex, nofollow")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)


class APICommonBehaviorTests(APITestMixin, SimpleTestCase):
    post_routes = (
        "api-v1-http-check",
        "api-v1-dns",
        "api-v1-redirects",
        "api-v1-tls",
        "api-v1-security-headers",
        "api-v1-ip",
        "api-v1-subnet",
        "api-v1-punycode",
    )

    def test_health_is_minimal_and_has_common_headers(self):
        response = self.client.get(reverse("api-v1-health"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"ok": True, "data": {"status": "ok", "api_version": "v1"}},
        )
        self.assert_api_headers(response)

    def test_public_json_posts_do_not_require_a_csrf_cookie(self):
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(
            reverse("api-v1-subnet"),
            data='{"cidr":"192.0.2.0/24"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])

    def test_wrong_methods_return_json_405_and_allow(self):
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(
            reverse("api-v1-health"), data="{}", content_type="application/json"
        )
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response["Allow"], "GET")
        self.assert_api_headers(response)
        for route_name in self.post_routes:
            with self.subTest(route_name=route_name):
                response = csrf_client.get(reverse(route_name))
                self.assertEqual(response.status_code, 405)
                self.assertEqual(response["Allow"], "POST")
                self.assertEqual(response.json()["error"]["code"], "method_not_allowed")
                self.assert_api_headers(response)

        response = csrf_client.put(
            reverse("api-v1-subnet"), data="{}", content_type="application/json"
        )
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response["Allow"], "POST")

    def test_malformed_non_object_and_empty_json_are_rejected(self):
        path = reverse("api-v1-subnet")
        cases = (
            ("{", "invalid_json"),
            ("[]", "invalid_json_object"),
            ('"text"', "invalid_json_object"),
            ("null", "invalid_json_object"),
            ("{}", "missing_field"),
        )
        for body, code in cases:
            with self.subTest(body=body):
                response = self.client.post(path, data=body, content_type="application/json")
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], code)
                self.assert_api_headers(response)

    def test_oversized_body_is_rejected(self):
        response = self.client.post(
            reverse("api-v1-subnet"),
            data=json.dumps({"cidr": "1" * 5000}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"]["code"], "request_too_large")

    def test_unknown_fields_wrong_content_type_and_query_are_rejected(self):
        unknown = self.post_json(
            "api-v1-subnet", {"cidr": "192.0.2.0/24", "extra": True}
        )
        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(unknown.json()["error"]["code"], "unknown_field")

        form = self.client.post(
            reverse("api-v1-subnet"), {"cidr": "192.0.2.0/24"}
        )
        self.assertEqual(form.status_code, 415)
        self.assertEqual(form.json()["error"]["code"], "unsupported_media_type")

        query = self.client.post(
            f'{reverse("api-v1-subnet")}?cidr=192.0.2.0/24',
            data="{}",
            content_type="application/json",
        )
        self.assertEqual(query.status_code, 400)
        self.assertEqual(query.json()["error"]["code"], "unexpected_query")

    def test_failures_never_expose_exception_text(self):
        with patch("core.api_views.calculate_subnet", side_effect=RuntimeError("/srv/secret")):
            response = self.post_json("api-v1-subnet", {"cidr": "192.0.2.0/24"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"]["code"], "internal_error")
        self.assertNotContains(response, "/srv/secret", status_code=500)

    def test_unknown_v1_paths_return_the_same_safe_json_format(self):
        response = self.client.get("/api/v1/does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "not_found")
        self.assert_api_headers(response)


class APIHTTPTests(APITestMixin, SimpleTestCase):
    @patch("core.api_views.safe_http_request")
    def test_public_url_is_returned_with_safe_headers_only(self, request):
        request.return_value = http_result(
            headers={
                "content-type": "text/html",
                "server": "Example",
                "set-cookie": "session=secret",
                "authorization": "Bearer secret",
                "x-forwarded-for": "10.0.0.1",
            }
        )
        response = self.post_json("api-v1-http-check", {"url": "example.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertEqual(data["url"], "https://example.com/")
        self.assertEqual(data["http_response_time_ms"], 24)
        self.assertEqual(data["headers"], {"Server": "Example", "Content-Type": "text/html"})
        self.assertNotContains(response, "session=secret")
        self.assert_api_headers(response)

    def test_unsafe_address_classes_are_rejected(self):
        values = (
            "http://127.0.0.1",
            "http://10.0.0.1",
            "http://169.254.169.254",
            "http://192.0.2.1",
            "http://[fd00::1]",
            "http://[::ffff:10.0.0.1]",
        )
        for value in values:
            with self.subTest(value=value):
                response = self.post_json("api-v1-http-check", {"url": value})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "non_public_target")

    @patch("core.network_utils._resolve_addresses")
    def test_mixed_public_and_private_dns_answers_fail_closed(self, resolve):
        resolve.return_value = ("8.8.8.8", "10.0.0.8")
        response = self.post_json(
            "api-v1-http-check", {"url": "https://example.com"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "non_public_target")

    def test_credentials_and_unsupported_ports_are_rejected(self):
        cases = (
            ("https://user:secret@example.com", "userinfo"),
            ("https://example.com:8443", "disallowed_port"),
        )
        for url, code in cases:
            with self.subTest(url=url):
                response = self.post_json("api-v1-http-check", {"url": url})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], code)

    @patch("core.network_utils._make_connection")
    @patch("core.network_utils._resolve_addresses")
    def test_redirect_to_private_target_is_revalidated(self, resolve, make_connection):
        resolve.return_value = ("8.8.8.8",)
        upstream = Mock()
        upstream.status = 302
        upstream.reason = "Found"
        upstream.getheaders.return_value = [("Location", "http://127.0.0.1/admin")]
        connection = Mock()
        connection.getresponse.return_value = upstream
        make_connection.return_value = connection

        response = self.post_json(
            "api-v1-redirects", {"url": "https://example.com"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "non_public_target")
        self.assertEqual(make_connection.call_count, 1)


class APIDNSTests(APITestMixin, SimpleTestCase):
    @patch("core.api_views.lookup_records")
    def test_supported_record_types_return_structured_arrays(self, lookup):
        samples = {
            "A": ("192.0.2.1", {"address": "192.0.2.1"}),
            "AAAA": ("2001:db8::1", {"address": "2001:db8::1"}),
            "CNAME": ("target.example.com.", {"target": "target.example.com"}),
            "MX": ("10 mail.example.com.", {"priority": 10, "exchange": "mail.example.com"}),
            "TXT": ('"v=spf1 -all"', {"value": '"v=spf1 -all"'}),
            "NS": ("ns1.example.com.", {"nameserver": "ns1.example.com"}),
        }
        for record_type, (raw, expected) in samples.items():
            with self.subTest(record_type=record_type):
                lookup.return_value = (
                    "example.com",
                    [{"type": record_type, "ttl": 300, "values": (raw,)}],
                )
                response = self.post_json(
                    "api-v1-dns", {"domain": "example.com", "type": record_type}
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["data"]["records"], [expected])

    def test_unsupported_type_and_invalid_domain_are_rejected(self):
        unsupported = self.post_json(
            "api-v1-dns", {"domain": "example.com", "type": "SOA"}
        )
        self.assertEqual(unsupported.status_code, 400)
        self.assertEqual(unsupported.json()["error"]["code"], "invalid_record_type")

        invalid = self.post_json(
            "api-v1-dns", {"domain": "not-a-domain", "type": "A"}
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()["error"]["code"], "invalid_host")


class APIRedirectAndSecurityHeaderTests(APITestMixin, SimpleTestCase):
    @patch("core.api_views.safe_http_request")
    def test_redirect_chain_is_structured_and_bounded_errors_are_safe(self, request):
        request.return_value = http_result(
            url="https://example.com/final",
            redirects=1,
            chain=(
                HTTPHop("http://example.com/", 301, "Moved", "https://example.com/final", 12),
                HTTPHop("https://example.com/final", 200, "OK", None, 18),
            ),
        )
        response = self.post_json(
            "api-v1-redirects", {"url": "http://example.com"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["redirect_count"], 1)
        self.assertEqual(response.json()["data"]["hops"][0]["status_code"], 301)

        request.side_effect = NetworkToolError(
            "redirect_limit", "The website exceeded the redirect limit."
        )
        limited = self.post_json(
            "api-v1-redirects", {"url": "https://example.com"}
        )
        self.assertEqual(limited.status_code, 400)
        self.assertEqual(limited.json()["error"]["code"], "redirect_limit")

    @patch("core.api_views.safe_http_request")
    def test_security_headers_are_neutral_and_exclude_cookies(self, request):
        request.return_value = http_result(
            headers={
                "strict-transport-security": "max-age=31536000",
                "set-cookie": "session=secret",
            }
        )
        response = self.post_json(
            "api-v1-security-headers", {"url": "https://example.com"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertTrue(data["headers"]["Strict-Transport-Security"]["present"])
        self.assertFalse(data["headers"]["Content-Security-Policy"]["present"])
        self.assertIn("not confirmation", data["note"])
        self.assertNotContains(response, "session=secret")


class APITLSAndIPTests(APITestMixin, SimpleTestCase):
    @patch("core.api_views.check_tls_certificate")
    def test_tls_returns_validated_safe_fields(self, checker):
        checker.return_value = TLSResult(
            hostname="example.com",
            subject="commonName=example.com",
            issuer="organizationName=Example CA",
            san_hostnames=("example.com",),
            valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            valid_until=datetime(2027, 1, 1, tzinfo=timezone.utc),
            days_remaining=94,
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
        )
        response = self.post_json("api-v1-tls", {"hostname": "example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            set(response.json()["data"]),
            {
                "hostname",
                "certificate_valid",
                "hostname_match",
                "valid_from",
                "valid_until",
                "days_remaining",
                "issuer",
            },
        )

    def test_tls_invalid_and_private_hosts_are_rejected(self):
        for hostname in ("bad", "localhost", "10.0.0.1", "example.com:8443"):
            with self.subTest(hostname=hostname):
                response = self.post_json("api-v1-tls", {"hostname": hostname})
                self.assertEqual(response.status_code, 400)

    @patch("core.network_utils._resolve_addresses")
    def test_tls_hostname_resolving_private_is_rejected(self, resolve):
        resolve.return_value = ("10.0.0.8",)
        response = self.post_json("api-v1-tls", {"hostname": "example.com"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "non_public_target")

    @patch("core.api_views.dbip_location")
    def test_ip_uses_dbip_allowlisted_fields_only(self, lookup):
        lookup.return_value = {
            "city": "Example City",
            "country_code": "US",
            "latitude": 1.5,
            "longitude": 2.5,
            "asn": 64500,
            "organization": "Must not escape",
            "timezone": "UTC",
            "postal_code": "00000",
        }
        response = self.post_json("api-v1-ip", {"ip": "8.8.8.8"})
        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertEqual(data["data_source"], "DB-IP City Lite")
        self.assertEqual(data["city"], "Example City")
        for forbidden in ("asn", "organization", "timezone", "postal_code"):
            self.assertNotIn(forbidden, data)
        lookup.assert_called_once()

    def test_ip_rejects_malformed_and_non_public_addresses(self):
        for value in ("not-an-ip", "10.0.0.1", "127.0.0.1", "169.254.1.1", "fd00::1"):
            with self.subTest(value=value):
                response = self.post_json("api-v1-ip", {"ip": value})
                self.assertEqual(response.status_code, 400)


class APILocalCalculationTests(APITestMixin, SimpleTestCase):
    def test_subnet_ipv4_ipv6_and_large_network_are_not_enumerated(self):
        ipv4 = self.post_json("api-v1-subnet", {"cidr": "192.0.2.42/24"})
        self.assertEqual(ipv4.status_code, 200)
        self.assertEqual(ipv4.json()["data"]["network"], "192.0.2.0")
        self.assertEqual(ipv4.json()["data"]["broadcast"], "192.0.2.255")

        ipv6 = self.post_json("api-v1-subnet", {"cidr": "2001:db8::1/64"})
        self.assertEqual(ipv6.status_code, 200)
        self.assertEqual(ipv6.json()["data"]["version"], 6)
        self.assertNotIn("broadcast", ipv6.json()["data"])

        large = self.post_json("api-v1-subnet", {"cidr": "::/0"})
        self.assertEqual(large.status_code, 200)
        self.assertEqual(large.json()["data"]["total"], 2**128)
        self.assertLess(len(large.content), 1000)

    def test_punycode_both_directions_and_invalid_input(self):
        unicode_response = self.post_json(
            "api-v1-punycode", {"value": "münchen.example"}
        )
        self.assertEqual(unicode_response.status_code, 200)
        self.assertEqual(
            unicode_response.json()["data"],
            {"ascii": "xn--mnchen-3ya.example", "unicode": "münchen.example"},
        )
        ascii_response = self.post_json(
            "api-v1-punycode", {"value": "xn--mnchen-3ya.example"}
        )
        self.assertEqual(ascii_response.json()["data"]["unicode"], "münchen.example")

        invalid = self.post_json("api-v1-punycode", {"value": "bad/domain"})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()["error"]["code"], "invalid_punycode")


class DeveloperDocumentationTests(SimpleTestCase):
    def test_developer_page_metadata_links_and_examples(self):
        response = self.client.get(reverse("developers"))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertEqual(html.count("<h1"), 1)
        self.assertContains(
            response,
            "Developer API – HTTP, DNS, TLS &amp; Network Diagnostics | WhatWebSees",
        )
        self.assertContains(response, '<meta name="description"')
        self.assertContains(
            response, 'rel="canonical" href="https://whatwebsees.com/developers/"'
        )
        self.assertNotContains(response, 'name="robots"')
        self.assertNotIn("X-Robots-Tag", response.headers)
        for path in (
            "/website-status/",
            "/dns-lookup/",
            "/redirect-checker/",
            "/ssl-checker/",
            "/security-headers/",
            "/ip-lookup/",
            "/subnet-calculator/",
            "/punycode-converter/",
        ):
            self.assertContains(response, f'href="{path}"')
        self.assertContains(response, "https://github.com/JakLjk/whatwebsees")
        self.assertContains(response, "curl -sS")
        self.assertContains(response, "urllib.request")
        self.assertContains(response, "await fetch")
        self.assertContains(response, "IP geolocation by DB-IP")

    def test_docs_are_in_sitemap_but_execution_routes_are_not(self):
        response = self.client.get(reverse("sitemap"))
        self.assertContains(
            response, "<loc>https://whatwebsees.com/developers/</loc>"
        )
        self.assertNotContains(response, "/api/v1/")
        self.assertNotContains(response, "/developers/api/")

    def test_compatibility_docs_route_redirects_to_canonical_page(self):
        response = self.client.get(reverse("developers-api"))
        self.assertEqual(response.status_code, 301)
        self.assertEqual(response["Location"], "/developers/")

    def test_navigation_about_and_relevant_tools_link_to_docs(self):
        for route_name in (
            "home",
            "about",
            "website-status",
            "dns-lookup",
            "download-time-calculator",
        ):
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))
                self.assertContains(response, "/developers/")


class NginxAPIRateLimitTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        config_path = (
            Path(__file__).resolve().parents[2] / "nginx" / "default.conf"
        )
        if not config_path.is_file():
            raise SkipTest(
                "nginx/default.conf is not included in the Django web image; "
                "deployment nginx configuration is validated separately."
            )
        cls.config = config_path.read_text()

    def test_api_rate_limit_zones_and_rates_exist(self):
        self.assertIn("zone=api_network_per_ip:10m rate=30r/m", self.config)
        self.assertIn("zone=api_local_per_ip:10m rate=120r/m", self.config)
        self.assertIn("zone=api_health_per_ip:10m rate=60r/m", self.config)
        self.assertIn("$normalized_client_ip", self.config)
        self.assertIn(
            "(http-check|dns|redirects|tls|security-headers|ip)$", self.config
        )
        self.assertIn("(subnet|punycode)$", self.config)
        self.assertIn('"GET:/api/v1/health"', self.config)

    def test_api_location_uses_limits_and_json_429(self):
        self.assertIn("location ^~ /api/v1/", self.config)
        self.assertIn("client_max_body_size 4k", self.config)
        self.assertIn("limit_req zone=api_network_per_ip burst=6 nodelay", self.config)
        self.assertIn("limit_req zone=api_local_per_ip burst=20 nodelay", self.config)
        self.assertIn("limit_req_status 429", self.config)
        self.assertIn('"code":"rate_limited"', self.config)
        self.assertIn('"code":"request_too_large"', self.config)
        self.assertIn('add_header X-Robots-Tag "noindex, nofollow" always', self.config)
