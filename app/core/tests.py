from django.test import SimpleTestCase
from django.urls import reverse


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
