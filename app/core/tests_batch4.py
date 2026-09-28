from unittest.mock import patch
from html import unescape
from re import search

from django.test import SimpleTestCase
from django.urls import reverse

from core.network_utils import HTTPHop, HTTPResult
from core.views import PUBLIC_PAGES, TOOL_PAGE_METADATA, TOOL_SUMMARIES


class SpeedTestDjangoFallbackTests(SimpleTestCase):
    def test_origin_fallback_is_small_non_streaming_503(self):
        response = self.client.get(
            reverse("speed-test-download"), {"size": "24m"}
        )

        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.streaming)
        self.assertLess(len(response.content), 256)
        self.assertEqual(
            response.json(), {"error": "edge_speed_test_unavailable"}
        )
        self.assertNotEqual(
            response.headers["Content-Type"], "application/octet-stream"
        )

    def test_origin_fallback_is_identified_uncacheable_and_noindex(self):
        response = self.client.get(reverse("speed-test-download"))

        self.assertEqual(
            response.headers["X-WWS-Speedtest-Backend"], "django-fallback"
        )
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Robots-Tag"], "noindex, nofollow")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_origin_never_serves_old_allowlisted_payloads(self):
        for choice in ("1m", "4m", "16m", "24m"):
            with self.subTest(choice=choice):
                response = self.client.get(
                    reverse("speed-test-download"), {"size": choice}
                )
                self.assertEqual(response.status_code, 503)
                self.assertFalse(response.streaming)


class BatchFourDownloadPageTests(SimpleTestCase):
    def test_page_keeps_calculator_and_adds_real_speed_test_ui(self):
        response = self.client.get(reverse("download-time-calculator"))

        self.assertContains(
            response,
            '<h1 id="page-title">Internet Speed Test &amp; Download Time Calculator</h1>',
        )
        for element_id in (
            "run-speed-test",
            "cancel-speed-test",
            "speed-test-state",
            "speed-test-progress",
            "speed-test-latency",
            "speed-test-download",
            "speed-test-upload",
            "download-calculator",
            "file-size",
            "speed",
            "download-result",
        ):
            with self.subTest(element_id=element_id):
                self.assertContains(response, f'id="{element_id}"')

    def test_browser_test_counts_stream_bytes_and_has_hard_limits(self):
        response = self.client.get(reverse("download-time-calculator"))

        for implementation_marker in (
            'latency: "/speed-test/ping/"',
            'download: "/speed-test/download/"',
            'upload: "/speed-test/upload/"',
            'downloadWarmup = {asset: "payload-1m.bin"',
            '{asset: "payload-1m.bin", bytes: mebibyte, streams: 1}',
            '{asset: "payload-4m.bin", bytes: 4 * mebibyte, streams: 2}',
            '{asset: "payload-16m.bin", bytes: 16 * mebibyte, streams: 3}',
            '{asset: "payload-24m.bin", bytes: 24 * mebibyte, streams: 4}',
            'uploadWarmup = {bytes: mebibyte, requests: 1}',
            '{bytes: 16 * mebibyte, requests: 2}',
            'cache: "no-store"',
            "response.body.getReader",
            "value.byteLength",
            "performance.now()",
            "new AbortController()",
            "maximumRuntimeMs = 35000",
            "maximumDownloadBytes = 154 * mebibyte",
            "maximumUploadBytes = 54 * mebibyte",
            "?nonce=${Date.now()}-${requestSequence += 1}",
            "median(",
            "/ 1000000",
        ):
            with self.subTest(marker=implementation_marker):
                self.assertContains(response, implementation_marker)

    def test_download_uses_concurrent_stage_body_timing_not_request_latency(self):
        response = self.client.get(reverse("download-time-calculator"))
        html = response.content.decode()

        self.assertIn(
            "firstHeadersReceived = Number.POSITIVE_INFINITY",
            html,
        )
        self.assertIn(
            "firstHeadersReceived = Math.min(firstHeadersReceived, headersReceived)",
            html,
        )
        self.assertIn(
            "transferDurationMs: Math.max(1, completed - firstHeadersReceived)",
            html,
        )
        self.assertIn(
            "bytes: received.reduce((total, bytes) => total + bytes, 0)",
            html,
        )
        self.assertIn(
            "mbps: (measurement.bytes * 8)",
            html,
        )
        self.assertIn("Promise.all(transfers)", html)
        self.assertNotIn("completed - requestStarted", html)

    def test_browser_rejects_incomplete_download_streams(self):
        response = self.client.get(reverse("download-time-calculator"))

        self.assertContains(
            response,
            'if (receivedBytes !== stage.bytes) throw new Error("incomplete_transfer")',
        )

    def test_client_requires_edge_marker_and_handles_unavailable_service(self):
        response = self.client.get(reverse("download-time-calculator"))

        self.assertContains(
            response,
            'response.headers.get("X-WWS-Speedtest-Backend") !== expectedBackend',
        )
        self.assertContains(response, 'workerBackend = "cloudflare-worker"')
        self.assertContains(
            response,
            'staticAssetBackend = "cloudflare-static-asset"',
        )
        self.assertContains(
            response,
            "verifyEdgeResponse(response, staticAssetBackend)",
        )
        self.assertContains(response, "Speed-test edge service is unavailable.")

    def test_latency_discards_warmup_and_upload_is_bounded_and_discarded(self):
        response = self.client.get(reverse("download-time-calculator"))

        self.assertContains(response, "index < 5")
        self.assertContains(response, "if (index > 0) samples.push")
        self.assertContains(response, "createUploadPayload")
        self.assertContains(response, "acknowledgedBytes !== expectedBytes")
        self.assertContains(response, "Temporary binary data is being streamed to Cloudflare and discarded")

    def test_page_explains_measurement_and_decimal_calculator_units(self):
        response = self.client.get(reverse("download-time-calculator"))

        self.assertContains(response, "not an ISP-certified line-speed measurement")
        self.assertContains(response, "HTTP latency")
        self.assertContains(response, "not ICMP ping")
        self.assertContains(response, "1 MB = 1,000,000 bytes")
        self.assertContains(response, "1 GB at 100 Mbps")
        self.assertContains(response, "100 GB at 1 Gbps")
        self.assertContains(response, "bits make one byte")
        self.assertContains(response, "Speed test result")
        self.assertContains(response, "Technical details and transfer limits")
        self.assertNotContains(response, "Cloudflare edge result")

    def test_worker_endpoints_are_not_in_sitemap_and_page_remains_indexable(self):
        response = self.client.get(reverse("sitemap"))

        for path in ("ping", "download", "upload"):
            self.assertNotContains(
                response,
                f"https://whatwebsees.com/speed-test/{path}/",
            )

        page = self.client.get(reverse("download-time-calculator"))
        self.assertEqual(page.status_code, 200)
        self.assertNotIn("X-Robots-Tag", page.headers)
        self.assertContains(
            page,
            '<link rel="canonical" href="https://whatwebsees.com/download-time-calculator/">',
        )


class PublicPagePolishTests(SimpleTestCase):
    def test_every_indexable_public_page_has_one_h1_and_canonical(self):
        for path in PUBLIC_PAGES:
            with self.subTest(path=path):
                response = self.client.get(path)
                html = response.content.decode()

                self.assertEqual(response.status_code, 200)
                self.assertEqual(html.count("<h1"), 1)
                self.assertIn("<title>", html)
                self.assertIn('<meta name="description"', html)
                self.assertIn(
                    f'rel="canonical" href="https://whatwebsees.com{path}"',
                    html,
                )
                self.assertNotIn('name="robots" content="noindex', html)
                self.assertNotIn("X-Robots-Tag", response.headers)

    def test_every_tool_has_one_h1_and_unique_search_metadata(self):
        titles = set()
        descriptions = set()

        for key, metadata in TOOL_PAGE_METADATA.items():
            with self.subTest(tool=key):
                response = self.client.get(metadata["path"])
                html = response.content.decode()
                title = search(r"<title>(.*?)</title>", html)
                description = search(
                    r'<meta name="description" content="([^"]+)">',
                    html,
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(html.count("<h1"), 1)
                self.assertIsNotNone(title)
                self.assertIsNotNone(description)
                titles.add(unescape(title.group(1)))
                descriptions.add(unescape(description.group(1)))

        self.assertEqual(len(titles), len(TOOL_PAGE_METADATA))
        self.assertEqual(len(descriptions), len(TOOL_PAGE_METADATA))

    def test_tools_index_uses_short_user_focused_summaries(self):
        response = self.client.get(reverse("tools"))
        rendered_summaries = {
            tool["description"]
            for group in response.context["tool_groups"]
            for tool in group["tools"]
        }

        self.assertEqual(set(TOOL_SUMMARIES), set(TOOL_PAGE_METADATA) - {"tools"})
        self.assertEqual(rendered_summaries, set(TOOL_SUMMARIES.values()))
        self.assertNotContains(response, "numeric socket")
        self.assertNotContains(response, "parser bounds")

    def test_sitemap_exactly_matches_intended_public_pages(self):
        response = self.client.get(reverse("sitemap"))
        xml = response.content.decode()

        self.assertEqual(xml.count("<loc>"), len(PUBLIC_PAGES))
        for path in PUBLIC_PAGES:
            self.assertIn(f"<loc>https://whatwebsees.com{path}</loc>", xml)
        self.assertNotIn("/speed-test/", xml)
        for internal_path in ("/health", "/headers", "/ip", "/location", "/network"):
            self.assertNotIn(f"<loc>https://whatwebsees.com{internal_path}</loc>", xml)


class BatchFourIntentPageTests(SimpleTestCase):
    def test_user_agent_checker_has_cautious_version_os_device_and_architecture(self):
        response = self.client.get(reverse("user-agent"))

        for text in (
            "Reported browser version",
            "Operating system",
            "Device category",
            "Reported architecture",
            "getHighEntropyValues",
            "reduced User-Agent",
            "reduce or spoof",
        ):
            with self.subTest(text=text):
                self.assertContains(response, text)

    def test_screen_checker_distinguishes_css_device_and_viewport_pixels(self):
        response = self.client.get(reverse("screen-resolution"))

        self.assertContains(response, "Estimated device-pixel dimensions")
        self.assertContains(response, "CSS pixel")
        self.assertContains(response, "physical display pixel")
        self.assertContains(response, "screen.orientation")
        self.assertNotContains(response, "navigator.geolocation")

    def test_ip_lookup_explains_provider_vpn_mobile_and_gps_limits(self):
        response = self.client.get(reverse("ip-lookup"))

        for text in (
            "geolocation database providers",
            "VPN and proxy",
            "mobile carriers",
            "not browser GPS",
            "/learn/how-ip-geolocation-works/",
            "/privacy-check/",
        ):
            with self.subTest(text=text):
                self.assertContains(response, text)

    @patch("core.views.safe_http_request")
    def test_redirect_result_has_clear_per_hop_fields_and_303_explanation(self, request):
        request.return_value = HTTPResult(
            url="https://example.com/final",
            status=200,
            reason="OK",
            elapsed_ms=30,
            redirects=1,
            headers={"content-type": "text/html"},
            chain=(
                HTTPHop(
                    url="https://example.com/start",
                    status=303,
                    reason="See Other",
                    location="https://example.com/final",
                    elapsed_ms=10,
                ),
                HTTPHop(
                    url="https://example.com/final",
                    status=200,
                    reason="OK",
                    location=None,
                    elapsed_ms=20,
                ),
            ),
        )

        response = self.client.post(
            reverse("redirect-checker"), {"url": "example.com/start"}
        )

        for text in (
            "Requested URL",
            "Status",
            "Location target",
            "Duration",
            "303 See Other",
            "POST/Redirect/GET",
            'href="/server-headers/"',
        ):
            with self.subTest(text=text):
                self.assertContains(response, text)
