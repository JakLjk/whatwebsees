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

    def test_home_does_not_embed_visitor_ip(self):
        visitor_ip = "198.51.100.42"

        response = self.client.get(reverse("home"), HTTP_X_REAL_IP=visitor_ip)

        self.assertNotContains(response, visitor_ip)


class HealthViewTests(SimpleTestCase):
    def test_health_returns_ok_without_database_access(self):
        response = self.client.get(reverse("health"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
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
