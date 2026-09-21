from django.test import SimpleTestCase
from django.urls import reverse


class HomeViewTests(SimpleTestCase):
    def test_home_returns_ok(self):
        response = self.client.get(reverse("home"))

        self.assertEqual(response.status_code, 200)

    def test_home_head_returns_ok(self):
        response = self.client.head(reverse("home"))

        self.assertEqual(response.status_code, 200)

    def test_home_returns_html(self):
        response = self.client.get(reverse("home"))

        self.assertEqual(
            response.headers["Content-Type"].split(";")[0], "text/html"
        )

    def test_home_does_not_set_cookies(self):
        response = self.client.get(reverse("home"))

        self.assertFalse(response.cookies)

    def test_home_rejects_post(self):
        response = self.client.post(reverse("home"))

        self.assertEqual(response.status_code, 405)

    def test_home_contains_main_title(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "What Does the Web See?")

    def test_home_contains_browser_and_device_section(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "Browser &amp; device")

    def test_home_contains_request_headers_section(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "Request headers")

    def test_home_contains_privacy_signals_section(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "Privacy signals")

    def test_home_contains_approximate_location_section(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "Approximate location")

    def test_home_contains_primary_information_summary(self):
        response = self.client.get(reverse("home"))

        for element_id in (
            "primary-information",
            "summary-ip",
            "summary-connection",
            "summary-network-provider",
            "summary-location",
            "summary-browser",
            "summary-platform",
            "summary-timezone",
        ):
            with self.subTest(element_id=element_id):
                self.assertContains(response, f'id="{element_id}"')

    def test_home_contains_network_asn_display(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, 'id="network-asn"')
        self.assertContains(response, "Autonomous system")

    def test_home_contains_network_provider_display(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, 'id="network-provider"')
        self.assertContains(response, 'id="summary-network-provider"')
        self.assertContains(response, "Network provider")

    def test_home_loads_network_diagnostics(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, 'fetch("/network"')
        self.assertContains(response, "loadNetwork()")
        self.assertContains(response, "`AS${data.network.asn}`")

    def test_home_contains_automatic_map_container(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, 'id="approximate-map-container"')
        self.assertContains(response, "OpenStreetMap")
        self.assertNotContains(response, "Load approximate map")
        self.assertNotContains(response, 'id="load-approximate-map"')

    def test_home_location_helpers_accept_numeric_coordinates(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, 'typeof value === "number"')
        self.assertContains(response, "Number.isFinite(value)")

    def test_home_creates_map_iframe_automatically_and_safely(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, 'document.createElement("iframe")')
        self.assertContains(response, "renderApproximateMap(location)")
        self.assertContains(
            response,
            "https://www.openstreetmap.org/export/embed.html",
        )
        self.assertContains(response, 'mapFrame.referrerPolicy = "no-referrer"')
        self.assertNotContains(response, "<iframe")

    def test_home_contains_progressive_disclosure_sections(self):
        response = self.client.get(reverse("home"))

        for element_id in (
            "connection-details",
            "location-details",
            "browser-device-details",
            "privacy-details",
            "advanced-technical-details",
        ):
            with self.subTest(element_id=element_id):
                self.assertContains(response, f'id="{element_id}"')

        self.assertGreaterEqual(response.content.count(b"<details"), 5)

    def test_home_does_not_use_browser_geolocation(self):
        response = self.client.get(reverse("home"))

        self.assertNotContains(response, "navigator.geolocation")

    def test_home_does_not_load_third_party_map_libraries(self):
        response = self.client.get(reverse("home"))

        for library_reference in (
            "leaflet",
            "maplibre",
            "maps.googleapis.com",
            "api.mapbox.com",
            "tile.openstreetmap.org",
        ):
            with self.subTest(library_reference=library_reference):
                self.assertNotContains(response, library_reference)

    def test_home_keeps_analytics_dynamically_consent_controlled(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "const loadGoogleAnalytics = () =>")
        self.assertContains(response, 'document.createElement("script")')
        self.assertContains(response, 'if (consent === "granted")')

    def test_home_contains_analytics_consent_controls(self):
        response = self.client.get(reverse("home"))

        for element_id in (
            "analytics-consent",
            "analytics-accept",
            "analytics-reject",
            "analytics-settings",
        ):
            with self.subTest(element_id=element_id):
                self.assertContains(response, f'id="{element_id}"')

    def test_home_contains_google_analytics_measurement_id(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "G-GJ3PP8PF5J")

    def test_home_uses_local_storage_only_for_analytics_consent(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "window.localStorage.getItem")
        self.assertContains(response, "window.localStorage.setItem")
        self.assertContains(response, "web-privacy-analytics-consent")

    def test_home_does_not_load_google_analytics_with_static_script_tag(self):
        response = self.client.get(reverse("home"))

        self.assertNotContains(
            response,
            '<script async src="https://www.googletagmanager.com/gtag/js',
        )

    def test_home_contains_privacy_signal_display_elements(self):
        response = self.client.get(reverse("home"))
        element_ids = (
            "cookies-enabled",
            "do-not-track",
            "global-privacy-control",
            "online-status",
            "javascript-status",
        )

        for element_id in element_ids:
            with self.subTest(element_id=element_id):
                self.assertContains(response, f'id="{element_id}"')

    def test_home_references_privacy_signal_apis(self):
        response = self.client.get(reverse("home"))
        api_references = (
            "navigator.cookieEnabled",
            "navigator.doNotTrack",
            "navigator.globalPrivacyControl",
            "navigator.onLine",
        )

        for api_reference in api_references:
            with self.subTest(api_reference=api_reference):
                self.assertContains(response, api_reference)

    def test_home_contains_browser_info_display_elements(self):
        response = self.client.get(reverse("home"))
        element_ids = (
            "browser-language",
            "preferred-languages",
            "time-zone",
            "screen-resolution",
            "viewport-size",
            "device-pixel-ratio",
            "color-depth",
            "reported-platform",
            "user-agent",
        )

        for element_id in element_ids:
            with self.subTest(element_id=element_id):
                self.assertContains(response, f'id="{element_id}"')

    def test_home_references_browser_language_api(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "navigator.language")

    def test_home_references_timezone_api(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "Intl.DateTimeFormat")

    def test_home_references_user_agent_api(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, "navigator.userAgent")

    def test_home_does_not_embed_visitor_ip(self):
        visitor_ip = "198.51.100.42"

        response = self.client.get(reverse("home"), HTTP_X_REAL_IP=visitor_ip)

        self.assertNotContains(response, visitor_ip)

    def test_home_does_not_embed_browser_request_headers(self):
        user_agent = "server-side-user-agent-marker"
        language = "server-side-language-marker"

        response = self.client.get(
            reverse("home"),
            HTTP_USER_AGENT=user_agent,
            HTTP_ACCEPT_LANGUAGE=language,
        )

        self.assertNotContains(response, user_agent)
        self.assertNotContains(response, language)


class HealthViewTests(SimpleTestCase):
    def test_health_returns_ok_without_database_access(self):
        response = self.client.get(reverse("health"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        self.assertFalse(response.cookies)


class RequestHeadersViewTests(SimpleTestCase):
    def test_get_returns_only_present_allowlisted_headers(self):
        supplied_headers = {
            "HTTP_USER_AGENT": ("User-Agent", "Test Browser/1.0"),
            "HTTP_ACCEPT": ("Accept", "text/html"),
            "HTTP_ACCEPT_LANGUAGE": ("Accept-Language", "en-GB,en;q=0.9"),
            "HTTP_ACCEPT_ENCODING": ("Accept-Encoding", "gzip, br"),
            "HTTP_DNT": ("DNT", "1"),
            "HTTP_SEC_GPC": ("Sec-GPC", "1"),
            "HTTP_SEC_CH_UA": ("Sec-CH-UA", '"Example";v="1"'),
            "HTTP_SEC_CH_UA_MOBILE": ("Sec-CH-UA-Mobile", "?0"),
            "HTTP_SEC_CH_UA_PLATFORM": ("Sec-CH-UA-Platform", '"Linux"'),
            "HTTP_SEC_FETCH_SITE": ("Sec-Fetch-Site", "same-origin"),
            "HTTP_SEC_FETCH_MODE": ("Sec-Fetch-Mode", "navigate"),
            "HTTP_SEC_FETCH_DEST": ("Sec-Fetch-Dest", "document"),
            "HTTP_UPGRADE_INSECURE_REQUESTS": (
                "Upgrade-Insecure-Requests",
                "1",
            ),
        }
        request_meta = {
            key: value for key, (_, value) in supplied_headers.items()
        }
        request_meta["HTTP_X_NOT_ALLOWLISTED"] = "must-not-be-returned"

        response = self.client.get(reverse("headers"), **request_meta)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "headers": {
                    name: value for name, value in supplied_headers.values()
                }
            },
        )

    def test_post_is_rejected(self):
        response = self.client.post(reverse("headers"))

        self.assertEqual(response.status_code, 405)

    def test_sensitive_proxy_and_auth_headers_are_never_returned(self):
        sensitive_headers = {
            "HTTP_COOKIE": ("Cookie", "session=secret"),
            "HTTP_AUTHORIZATION": ("Authorization", "Bearer secret"),
            "HTTP_X_FORWARDED_FOR": ("X-Forwarded-For", "198.51.100.1"),
            "HTTP_X_REAL_IP": ("X-Real-IP", "198.51.100.2"),
            "HTTP_CF_CONNECTING_IP": ("CF-Connecting-IP", "198.51.100.3"),
        }
        request_meta = {
            key: value for key, (_, value) in sensitive_headers.items()
        }

        response = self.client.get(reverse("headers"), **request_meta)
        returned_headers = response.json()["headers"]

        for header_name, header_value in sensitive_headers.values():
            with self.subTest(header_name=header_name):
                self.assertNotIn(header_name, returned_headers)
                self.assertNotIn(header_value, returned_headers.values())

    def test_response_is_private_and_not_cacheable(self):
        response = self.client.get(reverse("headers"))

        self.assertIn("private", response.headers["Cache-Control"])
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_response_does_not_set_cookies(self):
        response = self.client.get(reverse("headers"))

        self.assertFalse(response.cookies)


class LocationViewTests(SimpleTestCase):
    def test_get_maps_cloudflare_location_headers(self):
        supplied_headers = {
            "HTTP_CF_IPCITY": ("city", "Warsaw"),
            "HTTP_CF_IPCOUNTRY": ("country_code", "PL"),
            "HTTP_CF_IPCONTINENT": ("continent_code", "EU"),
            "HTTP_CF_IPLONGITUDE": ("longitude", "21.0122"),
            "HTTP_CF_IPLATITUDE": ("latitude", "52.2297"),
            "HTTP_CF_REGION": ("region", "Mazovia"),
            "HTTP_CF_REGION_CODE": ("region_code", "14"),
            "HTTP_CF_METRO_CODE": ("metro_code", "0"),
            "HTTP_CF_POSTAL_CODE": ("postal_code", "00-001"),
            "HTTP_CF_TIMEZONE": ("timezone", "Europe/Warsaw"),
        }
        request_meta = {
            header: value for header, (_, value) in supplied_headers.items()
        }

        response = self.client.get(reverse("location"), **request_meta)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "location": {
                    key: value for key, value in supplied_headers.values()
                }
            },
        )

    def test_dbip_fallback_fills_missing_cloudflare_coordinates(self):
        from unittest.mock import patch

        fallback = {
            "city": "Lutoryż",
            "region": "Subcarpathia",
            "country": "Poland",
            "country_code": "PL",
            "continent_code": "EU",
            "latitude": 49.9671,
            "longitude": 21.9124,
        }

        with patch(
            "core.views.dbip_location",
            return_value=fallback,
        ) as lookup:
            response = self.client.get(
                reverse("location"),
                HTTP_CF_IPCOUNTRY="PL",
                HTTP_X_REAL_IP="8.8.8.8",
            )

        location_data = response.json()["location"]

        self.assertEqual(location_data["country_code"], "PL")
        self.assertEqual(location_data["country"], "Poland")
        self.assertEqual(location_data["city"], "Lutoryż")
        self.assertEqual(location_data["region"], "Subcarpathia")
        self.assertEqual(location_data["latitude"], 49.9671)
        self.assertEqual(location_data["longitude"], 21.9124)
        lookup.assert_called_once()

    def test_dbip_fallback_is_skipped_when_cloudflare_has_coordinates(self):
        from unittest.mock import patch

        with patch("core.views.dbip_location") as lookup:
            response = self.client.get(
                reverse("location"),
                HTTP_CF_IPCOUNTRY="PL",
                HTTP_CF_IPCITY="Warsaw",
                HTTP_CF_IPLATITUDE="52.2297",
                HTTP_CF_IPLONGITUDE="21.0122",
                HTTP_X_REAL_IP="8.8.8.8",
            )

        location_data = response.json()["location"]

        self.assertEqual(location_data["city"], "Warsaw")
        self.assertEqual(location_data["latitude"], "52.2297")
        self.assertEqual(location_data["longitude"], "21.0122")
        lookup.assert_not_called()

    def test_post_is_rejected(self):
        response = self.client.post(reverse("location"))

        self.assertEqual(response.status_code, 405)

    def test_unrelated_and_sensitive_headers_are_excluded(self):
        response = self.client.get(
            reverse("location"),
            HTTP_CF_RAY="internal-marker",
            HTTP_X_ARBITRARY="arbitrary-marker",
            HTTP_X_REAL_IP="198.51.100.1",
            HTTP_X_FORWARDED_FOR="198.51.100.2",
            HTTP_COOKIE="session=secret",
            HTTP_AUTHORIZATION="Bearer secret",
        )

        self.assertEqual(response.json(), {"location": {}})

    def test_cf_connecting_ip_is_excluded(self):
        response = self.client.get(
            reverse("location"), HTTP_CF_CONNECTING_IP="198.51.100.3"
        )

        self.assertEqual(response.json(), {"location": {}})

    def test_response_is_private_and_not_cacheable(self):
        response = self.client.get(reverse("location"))

        self.assertIn("private", response.headers["Cache-Control"])
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_response_does_not_set_cookies(self):
        response = self.client.get(reverse("location"))

        self.assertFalse(response.cookies)

    def test_empty_location_headers_return_empty_object(self):
        response = self.client.get(reverse("location"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"location": {}})


class ProxySecurityTests(SimpleTestCase):
    def test_forwarded_https_request_is_secure(self):
        response = self.client.get(
            reverse("health"), HTTP_X_FORWARDED_PROTO="https"
        )

        self.assertTrue(response.wsgi_request.is_secure())

    def test_forwarded_http_request_is_not_secure(self):
        response = self.client.get(
            reverse("health"), HTTP_X_FORWARDED_PROTO="http"
        )

        self.assertFalse(response.wsgi_request.is_secure())


class ClientIpViewTests(SimpleTestCase):
    def test_public_ipv4(self):
        response = self.client.get(reverse("ip"), HTTP_X_REAL_IP="8.8.8.8")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"ip": "8.8.8.8", "version": 4, "is_public": True},
        )

    def test_public_ipv6(self):
        response = self.client.get(
            reverse("ip"), HTTP_X_REAL_IP="2001:4860:4860::8888"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "ip": "2001:4860:4860::8888",
                "version": 6,
                "is_public": True,
            },
        )

    def test_ipv6_is_canonicalized(self):
        response = self.client.get(
            reverse("ip"),
            HTTP_X_REAL_IP="2001:4860:4860:0:0:0:0:8888",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ip"], "2001:4860:4860::8888")

    def test_non_public_address(self):
        response = self.client.get(
            reverse("ip"), HTTP_X_REAL_IP="192.168.1.10"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"ip": "192.168.1.10", "version": 4, "is_public": False},
        )

    def test_missing_x_real_ip_returns_service_unavailable(self):
        response = self.client.get(
            reverse("ip"), HTTP_X_FORWARDED_FOR="8.8.8.8"
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": "client_ip_unavailable"})

    def test_empty_x_real_ip_returns_service_unavailable(self):
        response = self.client.get(reverse("ip"), HTTP_X_REAL_IP="")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": "client_ip_unavailable"})

    def test_malformed_x_real_ip_returns_service_unavailable(self):
        response = self.client.get(
            reverse("ip"), HTTP_X_REAL_IP="not-an-ip-address"
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": "client_ip_unavailable"})

    def test_surrounding_whitespace_is_stripped(self):
        response = self.client.get(
            reverse("ip"), HTTP_X_REAL_IP="  8.8.8.8\t"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ip"], "8.8.8.8")

    def test_post_is_rejected(self):
        response = self.client.post(reverse("ip"), HTTP_X_REAL_IP="8.8.8.8")

        self.assertEqual(response.status_code, 405)

    def test_successful_response_does_not_set_cookies(self):
        response = self.client.get(reverse("ip"), HTTP_X_REAL_IP="8.8.8.8")

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.cookies)

    def test_successful_response_is_not_cacheable(self):
        response = self.client.get(reverse("ip"), HTTP_X_REAL_IP="8.8.8.8")

        self.assertEqual(response.status_code, 200)
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertIn("private", response.headers["Cache-Control"])



class CloudflareLocationEncodingTests(SimpleTestCase):
    def test_location_recovers_utf8_cloudflare_header_value(self):
        response = self.client.get(
            reverse("location"),
            HTTP_CF_IPCITY="Ruda \u00c5\u009al\u00c4\u0085ska",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["location"]["city"],
            "Ruda Śląska",
        )

    def test_location_keeps_already_correct_unicode(self):
        response = self.client.get(
            reverse("location"),
            HTTP_CF_IPCITY="Ruda Śląska",
        )

        self.assertEqual(
            response.json()["location"]["city"],
            "Ruda Śląska",
        )



class SeoFoundationTests(SimpleTestCase):
    def test_home_contains_production_seo_metadata(self):
        response = self.client.get(reverse("home"))

        self.assertContains(
            response,
            "What Is My IP? IP Address, Location &amp; Browser | WhatWebSees",
        )
        self.assertContains(
            response,
            'rel="canonical" href="https://whatwebsees.com/"',
        )
        self.assertContains(response, 'property="og:title"')
        self.assertContains(response, 'property="og:url"')
        self.assertContains(response, 'name="twitter:card"')

    def test_robots_txt(self):
        response = self.client.get(reverse("robots"))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers["Content-Type"].startswith("text/plain")
        )
        self.assertContains(response, "User-agent: *")
        self.assertContains(response, "Allow: /")
        self.assertContains(
            response,
            "Sitemap: https://whatwebsees.com/sitemap.xml",
        )

    def test_sitemap_xml(self):
        response = self.client.get(reverse("sitemap"))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers["Content-Type"].startswith("application/xml")
        )
        self.assertContains(response, "<urlset")
        self.assertContains(
            response,
            "<loc>https://whatwebsees.com/</loc>",
        )

    def test_health_is_not_indexable(self):
        response = self.client.get(reverse("health"))

        self.assertEqual(
            response.headers.get("X-Robots-Tag"),
            "noindex, nofollow",
        )

    def test_location_api_is_not_indexable(self):
        response = self.client.get(reverse("location"))

        self.assertEqual(
            response.headers.get("X-Robots-Tag"),
            "noindex, nofollow",
        )



class NetworkViewTests(SimpleTestCase):
    def test_network_returns_asn(self):
        response = self.client.get(
            reverse("network"),
            HTTP_X_VISITOR_ASN="5617",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"network": {"asn": 5617}},
        )

    def test_network_returns_asn_and_organization(self):
        response = self.client.get(
            reverse("network"),
            HTTP_X_VISITOR_ASN="9009",
            HTTP_X_VISITOR_AS_ORGANIZATION="M247 Europe SRL",
        )

        self.assertEqual(
            response.json(),
            {
                "network": {
                    "asn": 9009,
                    "organization": "M247 Europe SRL",
                }
            },
        )

    def test_network_returns_organization_without_asn(self):
        response = self.client.get(
            reverse("network"),
            HTTP_X_VISITOR_AS_ORGANIZATION="Example Network",
        )

        self.assertEqual(
            response.json(),
            {
                "network": {
                    "organization": "Example Network",
                }
            },
        )

    def test_network_without_asn_returns_empty_object(self):
        response = self.client.get(reverse("network"))

        self.assertEqual(
            response.json(),
            {"network": {}},
        )

    def test_network_rejects_invalid_asn(self):
        response = self.client.get(
            reverse("network"),
            HTTP_X_VISITOR_ASN="not-an-asn",
        )

        self.assertEqual(
            response.json(),
            {"network": {}},
        )

    def test_network_is_private_and_not_indexable(self):
        response = self.client.get(
            reverse("network"),
            HTTP_X_VISITOR_ASN="5617",
        )

        self.assertEqual(
            response.headers.get("X-Robots-Tag"),
            "noindex, nofollow",
        )
        self.assertIn("private", response.headers["Cache-Control"])
        self.assertIn("no-store", response.headers["Cache-Control"])


class PublicToolPageTests(SimpleTestCase):
    pages = (
        ("tools", "Privacy &amp; Browser Tools", "/tools/"),
        ("user-agent", "User Agent Checker", "/user-agent/"),
        ("browser-check", "Browser Checker", "/browser-check/"),
        (
            "screen-resolution",
            "Screen Resolution Checker",
            "/screen-resolution/",
        ),
        ("http-headers", "HTTP Headers Checker", "/http-headers/"),
        (
            "privacy-check",
            "Browser Privacy Signals Checker",
            "/privacy-check/",
        ),
        ("webgl", "WebGL &amp; GPU Checker", "/webgl/"),
        (
            "canvas-fingerprint",
            "Canvas Fingerprint Test",
            "/canvas-fingerprint/",
        ),
    )

    def test_each_public_tool_route_returns_ok_with_expected_h1(self):
        for route_name, expected_heading, _ in self.pages:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))

                self.assertEqual(response.status_code, 200)
                self.assertContains(response, f'<h1 id="page-title">{expected_heading}</h1>')

    def test_each_public_tool_page_has_its_production_canonical(self):
        for route_name, _, path in self.pages:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))

                self.assertContains(
                    response,
                    f'rel="canonical" href="https://whatwebsees.com{path}"',
                )

    def test_tool_pages_have_unique_titles_and_descriptions(self):
        from html import unescape
        from re import search

        titles = set()
        descriptions = set()

        for route_name, _, _ in self.pages:
            response = self.client.get(reverse(route_name))
            html = response.content.decode()
            title_match = search(r"<title>(.*?)</title>", html)
            description_match = search(
                r'<meta name="description" content="([^"]+)">',
                html,
            )

            self.assertIsNotNone(title_match)
            self.assertIsNotNone(description_match)
            titles.add(unescape(title_match.group(1)))
            descriptions.add(unescape(description_match.group(1)))

        self.assertEqual(len(titles), len(self.pages))
        self.assertEqual(len(descriptions), len(self.pages))

    def test_tool_pages_have_social_metadata(self):
        for route_name, _, _ in self.pages:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))

                self.assertContains(response, 'property="og:title"')
                self.assertContains(response, 'property="og:description"')
                self.assertContains(response, 'property="og:url"')
                self.assertContains(response, 'name="twitter:card"')
                self.assertContains(response, 'name="twitter:title"')
                self.assertContains(response, 'name="twitter:description"')

    def test_public_tool_pages_are_not_marked_noindex(self):
        for route_name, _, _ in self.pages:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))

                self.assertNotContains(response, 'name="robots"')
                self.assertNotIn("X-Robots-Tag", response.headers)

    def test_public_tool_pages_do_not_set_cookies(self):
        for route_name, _, _ in self.pages:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))

                self.assertFalse(response.cookies)

    def test_tool_pages_do_not_use_browser_geolocation(self):
        for route_name, _, _ in self.pages:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))

                self.assertNotContains(response, "navigator.geolocation")

    def test_diagnostic_pages_do_not_embed_server_side_visitor_data(self):
        markers = (
            "198.51.100.42",
            "server-side-user-agent-marker",
            "server-side-language-marker",
        )
        diagnostic_routes = [page[0] for page in self.pages if page[0] != "tools"]

        for route_name in diagnostic_routes:
            with self.subTest(route_name=route_name):
                response = self.client.get(
                    reverse(route_name),
                    HTTP_X_REAL_IP=markers[0],
                    HTTP_USER_AGENT=markers[1],
                    HTTP_ACCEPT_LANGUAGE=markers[2],
                )

                for marker in markers:
                    self.assertNotContains(response, marker)

    def test_home_links_to_tools_and_tools_links_to_every_tool(self):
        self.assertContains(self.client.get(reverse("home")), 'href="/tools/"')
        response = self.client.get(reverse("tools"))

        for route_name, _, _ in self.pages[1:]:
            with self.subTest(route_name=route_name):
                self.assertContains(response, f'href="{reverse(route_name)}"')

    def test_tool_pages_preserve_consent_controlled_analytics(self):
        response = self.client.get(reverse("tools"))

        self.assertContains(response, "web-privacy-analytics-consent")
        self.assertContains(response, 'if (consent === "granted")')
        self.assertContains(response, 'document.createElement("script")')
        self.assertNotContains(
            response,
            '<script async src="https://www.googletagmanager.com/gtag/js',
        )

    def test_http_headers_page_uses_existing_safe_endpoint(self):
        response = self.client.get(reverse("http-headers"))

        self.assertContains(response, 'fetch("/headers"')
        self.assertContains(response, "Selected safe headers")

    def test_user_agent_page_references_expected_browser_apis(self):
        response = self.client.get(reverse("user-agent"))

        for api_reference in (
            "navigator.userAgent",
            "navigator.platform",
            "navigator.vendor",
            "navigator.language",
            "navigator.languages",
            "navigator.userAgentData",
            "navigator.clipboard",
        ):
            with self.subTest(api_reference=api_reference):
                self.assertContains(response, api_reference)

    def test_screen_page_references_screen_and_viewport_apis(self):
        response = self.client.get(reverse("screen-resolution"))

        for api_reference in (
            "screen.width",
            "screen.height",
            "screen.availWidth",
            "screen.colorDepth",
            "window.innerWidth",
            "window.devicePixelRatio",
            "screen.orientation",
            "window.requestAnimationFrame",
        ):
            with self.subTest(api_reference=api_reference):
                self.assertContains(response, api_reference)

    def test_privacy_page_references_privacy_signal_apis(self):
        response = self.client.get(reverse("privacy-check"))

        for api_reference in (
            "navigator.cookieEnabled",
            "navigator.doNotTrack",
            "navigator.globalPrivacyControl",
            "navigator.onLine",
            "navigator.language",
            "navigator.userAgentData",
        ):
            with self.subTest(api_reference=api_reference):
                self.assertContains(response, api_reference)

    def test_webgl_page_tries_webgl2_then_webgl(self):
        response = self.client.get(reverse("webgl"))

        html = response.content.decode()
        webgl2_position = html.index('getContext("webgl2")')
        webgl_position = html.index('getContext("webgl")')
        self.assertLess(webgl2_position, webgl_position)
        self.assertContains(response, "WEBGL_debug_renderer_info")

    def test_canvas_page_requires_explicit_action_and_uses_sha256(self):
        response = self.client.get(reverse("canvas-fingerprint"))

        self.assertContains(response, 'id="run-canvas-test"')
        self.assertContains(response, "Run canvas test")
        self.assertContains(response, 'addEventListener("click", runCanvasTest)')
        self.assertContains(response, 'digest("SHA-256"')
        self.assertNotContains(response, "runCanvasTest();")

    def test_local_only_pages_do_not_make_diagnostic_network_requests(self):
        for route_name in (
            "browser-check",
            "screen-resolution",
            "privacy-check",
            "webgl",
            "canvas-fingerprint",
        ):
            with self.subTest(route_name=route_name):
                self.assertNotContains(
                    self.client.get(reverse(route_name)),
                    "fetch(",
                )


class ToolSitemapAndApiIndexingTests(SimpleTestCase):
    def test_sitemap_contains_all_public_pages_and_no_api_endpoints(self):
        response = self.client.get(reverse("sitemap"))
        public_paths = (
            "",
            "tools/",
            "user-agent/",
            "browser-check/",
            "screen-resolution/",
            "http-headers/",
            "privacy-check/",
            "webgl/",
            "canvas-fingerprint/",
        )

        for path in public_paths:
            with self.subTest(path=path):
                self.assertContains(
                    response,
                    f"<loc>https://whatwebsees.com/{path}</loc>",
                )

        for api_path in ("health", "headers", "ip", "location", "network"):
            with self.subTest(api_path=api_path):
                self.assertNotContains(
                    response,
                    f"<loc>https://whatwebsees.com/{api_path}</loc>",
                )

    def test_all_api_endpoints_remain_noindex(self):
        request_options = {
            "health": {},
            "headers": {},
            "ip": {"HTTP_X_REAL_IP": "8.8.8.8"},
            "location": {},
            "network": {},
        }

        for route_name, options in request_options.items():
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name), **options)

                self.assertEqual(
                    response.headers.get("X-Robots-Tag"),
                    "noindex, nofollow",
                )

    def test_backend_header_allowlist_has_no_sensitive_names(self):
        from core.views import REQUEST_HEADER_ALLOWLIST

        forbidden = {
            "Cookie",
            "Authorization",
            "CF-Connecting-IP",
            "X-Real-IP",
            "X-Forwarded-For",
            "CF-Ray",
        }

        self.assertTrue(forbidden.isdisjoint(REQUEST_HEADER_ALLOWLIST))
