from django.test import SimpleTestCase
from django.urls import reverse


class HealthViewTests(SimpleTestCase):
    def test_health_returns_ok_without_database_access(self):
        response = self.client.get(reverse("health"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        self.assertFalse(response.cookies)
