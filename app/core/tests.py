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
