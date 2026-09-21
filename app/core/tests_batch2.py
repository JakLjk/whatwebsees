from datetime import datetime
from ipaddress import ip_address
from unittest.mock import Mock, patch

from django.test import SimpleTestCase
from django.urls import reverse

from core.network_utils import (
    HTTPResult,
    NetworkToolError,
    _connect_to_ip,
    check_tls_certificate,
    is_public_address,
    normalize_http_url,
    resolve_public_host,
    safe_http_request,
)


class BatchTwoPublicPageTests(SimpleTestCase):
    pages = (
        ("ip-lookup", "IP Address Lookup", "/ip-lookup/"),
        ("ip-address-checker", "IP Address Checker", "/ip-address-checker/"),
        ("dns-lookup", "DNS Lookup", "/dns-lookup/"),
        ("reverse-dns", "Reverse DNS Lookup", "/reverse-dns/"),
        ("hostname-lookup", "Hostname Lookup", "/hostname-lookup/"),
        ("ssl-checker", "SSL Certificate Checker", "/ssl-checker/"),
        ("website-status", "Website Status &amp; Response Time Checker", "/website-status/"),
        ("server-headers", "Server Headers Checker", "/server-headers/"),
        ("subnet-calculator", "Subnet / CIDR Calculator", "/subnet-calculator/"),
        ("password-strength", "Password Strength Checker", "/password-strength/"),
        ("punycode-converter", "Punycode / IDN Converter", "/punycode-converter/"),
        ("download-time-calculator", "Download Time Calculator", "/download-time-calculator/"),
    )

    def test_each_page_has_complete_indexable_metadata(self):
        for route_name, heading, path in self.pages:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, f'<h1 id="page-title">{heading}</h1>')
                self.assertContains(response, "<title>")
                self.assertContains(response, '<meta name="description"')
                self.assertContains(response, f'rel="canonical" href="https://whatwebsees.com{path}"')
                self.assertContains(response, 'property="og:title"')
                self.assertContains(response, 'property="og:description"')
                self.assertContains(response, 'property="og:url"')
                self.assertContains(response, 'name="twitter:title"')
                self.assertNotContains(response, 'name="robots"')
                self.assertNotIn("X-Robots-Tag", response.headers)

    def test_each_page_is_in_sitemap_and_hub(self):
        sitemap = self.client.get(reverse("sitemap"))
        hub = self.client.get(reverse("tools"))
        for route_name, _, path in self.pages:
            with self.subTest(route_name=route_name):
                self.assertContains(sitemap, f"<loc>https://whatwebsees.com{path}</loc>")
                self.assertContains(hub, f'href="{path}"')

    def test_each_individual_page_has_breadcrumb_and_related_tools(self):
        for route_name, _, _ in self.pages:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))
                self.assertContains(response, '"@type": "BreadcrumbList"')
                self.assertContains(response, 'id="related-tools-title"')

    def test_navigation_is_shared_and_accessible(self):
        for route_name in ("home", "tools", "dns-lookup"):
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))
                self.assertContains(response, '<details class="tools-menu">')
                self.assertContains(response, "IP &amp; Network")
                self.assertContains(response, "Website Diagnostics")
                self.assertContains(response, "Security &amp; Utilities")


class PublicAddressSafetyTests(SimpleTestCase):
    forbidden_addresses = (
        "127.0.0.1",
        "127.1.2.3",
        "::1",
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "255.255.255.255",
        "fc00::1",
        "fd00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::ffff:192.168.1.1",
    )

    def test_forbidden_address_classes_are_rejected(self):
        for address in self.forbidden_addresses:
            with self.subTest(address=address):
                self.assertFalse(is_public_address(address))

    def test_known_global_addresses_are_accepted(self):
        self.assertTrue(is_public_address("8.8.8.8"))
        self.assertTrue(is_public_address("2001:4860:4860::8888"))

    @patch("core.network_utils._resolve_addresses")
    def test_hostname_resolving_only_private_is_rejected(self, resolve):
        resolve.return_value = ("10.0.0.8",)
        with self.assertRaisesRegex(NetworkToolError, "non-public"):
            resolve_public_host("example.com", 443)

    @patch("core.network_utils._resolve_addresses")
    def test_mixed_public_and_private_answers_fail_closed(self, resolve):
        resolve.return_value = ("8.8.8.8", "192.168.1.8")
        with self.assertRaises(NetworkToolError) as raised:
            resolve_public_host("example.com", 443)
        self.assertEqual(raised.exception.code, "non_public_target")

    def test_invalid_and_dangerous_urls_are_rejected(self):
        cases = (
            ("not a url", "invalid_host"),
            ("ftp://example.com/file", "unsupported_scheme"),
            ("gopher://example.com/1", "unsupported_scheme"),
            ("file:///etc/passwd", "unsupported_scheme"),
            ("https://user:secret@example.com/", "userinfo"),
            ("https://example.com:8443/", "disallowed_port"),
        )
        for value, code in cases:
            with self.subTest(value=value):
                with self.assertRaises(NetworkToolError) as raised:
                    normalize_http_url(value)
                self.assertEqual(raised.exception.code, code)

    def test_local_and_internal_names_are_rejected(self):
        for hostname in ("localhost", "printer.local", "service.internal", "hidden.onion"):
            with self.subTest(hostname=hostname):
                with self.assertRaises(NetworkToolError):
                    resolve_public_host(hostname, 443)

    @patch("core.network_utils.socket.getaddrinfo")
    @patch("core.network_utils.socket.socket")
    def test_pinned_connection_uses_numeric_socket_without_dns(self, socket_factory, getaddrinfo):
        connection = socket_factory.return_value
        result = _connect_to_ip("2001:4860:4860::8888", 443, 4)
        self.assertIs(result, connection)
        socket_factory.assert_called_once()
        connection.connect.assert_called_once_with(("2001:4860:4860::8888", 443, 0, 0))
        getaddrinfo.assert_not_called()

    @patch("core.network_utils._make_connection")
    @patch("core.network_utils._resolve_addresses")
    def test_redirect_from_public_hostname_to_private_ip_is_rejected(self, resolve, make_connection):
        resolve.return_value = ("8.8.8.8",)
        response = Mock()
        response.status = 302
        response.reason = "Found"
        response.getheaders.return_value = [("Location", "http://127.0.0.1/admin")]
        connection = Mock()
        connection.getresponse.return_value = response
        make_connection.return_value = connection

        with self.assertRaises(NetworkToolError) as raised:
            safe_http_request("https://example.com/")
        self.assertEqual(raised.exception.code, "non_public_target")
        self.assertEqual(make_connection.call_count, 1)


class TLSUtilityTests(SimpleTestCase):
    @patch("core.network_utils.ssl.create_default_context")
    @patch("core.network_utils._connect_to_ip")
    @patch("core.network_utils.resolve_public_host")
    def test_certificate_fields_are_parsed(self, resolve, create_connection, create_context):
        resolve.return_value = Mock(hostname="example.com", addresses=("8.8.8.8",))
        raw_socket = Mock()
        create_connection.return_value = raw_socket
        tls_socket = Mock()
        tls_socket.__enter__ = Mock(return_value=tls_socket)
        tls_socket.__exit__ = Mock(return_value=False)
        tls_socket.getpeercert.return_value = {
            "subject": ((('commonName', 'example.com'),),),
            "issuer": ((('organizationName', 'Example CA'),),),
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2030 GMT",
        }
        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        create_context.return_value.wrap_socket.return_value = tls_socket

        result = check_tls_certificate("example.com")

        self.assertEqual(result.subject, "commonName=example.com")
        self.assertEqual(result.issuer, "organizationName=Example CA")
        self.assertEqual(result.san_hostnames, ("example.com", "www.example.com"))
        self.assertIsInstance(result.valid_until, datetime)
        self.assertEqual(result.tls_version, "TLSv1.3")
        create_context.return_value.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname="example.com"
        )


class BatchTwoToolBehaviorTests(SimpleTestCase):
    def test_invalid_ip_lookup_is_friendly(self):
        response = self.client.post(reverse("ip-lookup"), {"ip": "not-an-ip"})
        self.assertContains(response, "Enter a valid IPv4 or IPv6 address.")
        self.assertNotContains(response, "Traceback")
        self.assertIn("private", response.headers["Cache-Control"])
        self.assertIn("no-store", response.headers["Cache-Control"])

    @patch("core.views.dbip_location")
    def test_private_ip_skips_geolocation(self, lookup):
        response = self.client.post(reverse("ip-lookup"), {"ip": "192.168.1.10"})
        self.assertContains(response, "Public geolocation does not apply")
        lookup.assert_not_called()

    def test_ip_checker_renders_ipv4_mapped_address(self):
        response = self.client.post(
            reverse("ip-address-checker"), {"ip": "::ffff:192.168.1.1"}
        )
        self.assertContains(response, "IPv4-mapped address")
        self.assertContains(response, "192.168.1.1")

    @patch("core.views.lookup_records")
    def test_dns_record_rendering(self, lookup):
        lookup.return_value = (
            "example.com",
            [{"type": "MX", "ttl": 300, "values": ("10 mail.example.com.",)}],
        )
        response = self.client.post(
            reverse("dns-lookup"), {"domain": "example.com", "record_type": "MX"}
        )
        self.assertContains(response, "MX records")
        self.assertContains(response, "TTL: 300 seconds")
        self.assertContains(response, "10 mail.example.com.")

    @patch("core.views.safe_http_request")
    def test_server_headers_excludes_set_cookie(self, request):
        request.return_value = HTTPResult(
            url="https://example.com/",
            status=200,
            reason="OK",
            elapsed_ms=20,
            redirects=0,
            headers={"server": "Example", "set-cookie": "session=top-secret"},
        )
        response = self.client.post(reverse("server-headers"), {"url": "example.com"})
        self.assertContains(response, "Example")
        self.assertNotContains(response, "session=top-secret")

    def test_subnet_31_and_32_semantics(self):
        cases = (
            ("192.0.2.0/31", "Both addresses can be used", "2"),
            ("192.0.2.7/32", "one host address", "1"),
        )
        for cidr, note, count in cases:
            with self.subTest(cidr=cidr):
                response = self.client.post(reverse("subnet-calculator"), {"cidr": cidr})
                self.assertContains(response, note)
                self.assertContains(response, f"<dd>{count}</dd>", html=True)

    def test_punycode_conversion_both_directions(self):
        unicode_response = self.client.post(
            reverse("punycode-converter"), {"domain": "münchen.example"}
        )
        self.assertContains(unicode_response, "xn--mnchen-3ya.example")
        ascii_response = self.client.post(
            reverse("punycode-converter"), {"domain": "xn--mnchen-3ya.example"}
        )
        self.assertContains(ascii_response, "münchen.example")

    def test_password_checker_has_no_submission_or_password_storage(self):
        response = self.client.get(reverse("password-strength"))
        html = response.content.decode()
        self.assertNotIn('name="password"', html)
        self.assertNotIn('fetch(', html)
        password_script = html[html.index("const password ="):html.index("</script>", html.index("const password ="))]
        self.assertNotIn("localStorage", password_script)
        self.assertNotIn("sessionStorage", password_script)
        self.assertIn("assessPassword", password_script)

    def test_download_calculator_contains_local_calculation(self):
        response = self.client.get(reverse("download-time-calculator"))
        self.assertContains(response, "calculateDownloadTime")
        self.assertContains(response, "sizeFactors")
        self.assertContains(response, "speedFactors")
        self.assertNotContains(response, "fetch(")

    def test_no_new_private_endpoints_were_added_to_sitemap(self):
        response = self.client.get(reverse("sitemap"))
        for path in ("health", "headers", "ip", "location", "network"):
            self.assertNotContains(response, f"https://whatwebsees.com/{path}</loc>")


class HeaderAllowlistTests(SimpleTestCase):
    def test_server_response_allowlist_excludes_sensitive_headers(self):
        from core.views import SERVER_HEADER_ALLOWLIST

        names = {name for name, _ in SERVER_HEADER_ALLOWLIST}
        self.assertNotIn("set-cookie", names)
        self.assertNotIn("www-authenticate", names)
        self.assertNotIn("authorization", names)
