from ipaddress import ip_address

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils.cache import patch_cache_control
from django.views.decorators.http import require_GET, require_safe


REQUEST_HEADER_ALLOWLIST = (
    "User-Agent",
    "Accept",
    "Accept-Language",
    "Accept-Encoding",
    "DNT",
    "Sec-GPC",
    "Sec-CH-UA",
    "Sec-CH-UA-Mobile",
    "Sec-CH-UA-Platform",
    "Sec-Fetch-Site",
    "Sec-Fetch-Mode",
    "Sec-Fetch-Dest",
    "Upgrade-Insecure-Requests",
)

CLOUDFLARE_LOCATION_HEADERS = (
    ("CF-IPCity", "city"),
    ("CF-IPCountry", "country_code"),
    ("CF-IPContinent", "continent_code"),
    ("CF-IPLongitude", "longitude"),
    ("CF-IPLatitude", "latitude"),
    ("CF-Region", "region"),
    ("CF-Region-Code", "region_code"),
    ("CF-Metro-Code", "metro_code"),
    ("CF-Postal-Code", "postal_code"),
    ("CF-Timezone", "timezone"),
)


@require_safe
def robots_txt(request):
    content = """User-agent: *
Allow: /

Sitemap: https://whatwebsees.com/sitemap.xml
"""
    return HttpResponse(content, content_type="text/plain; charset=utf-8")


@require_safe
def sitemap_xml(request):
    content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://whatwebsees.com/</loc>
  </url>
</urlset>
"""
    return HttpResponse(content, content_type="application/xml; charset=utf-8")


@require_safe
def home(request):
    return render(request, "core/home.html")


@require_GET
def health(request):
    response = JsonResponse({"status": "ok"})
    response["X-Robots-Tag"] = "noindex, nofollow"
    return response


def private_json_response(data, *, status=200):
    response = JsonResponse(data, status=status)
    response["X-Robots-Tag"] = "noindex, nofollow"
    patch_cache_control(response, private=True, no_store=True)
    return response


@require_GET
def network(request):
    value = request.headers.get("X-Visitor-ASN", "").strip()

    try:
        asn = int(value)
    except ValueError:
        asn = 0

    if not 1 <= asn <= 4294967295:
        return private_json_response({"network": {}})

    return private_json_response(
        {
            "network": {
                "asn": asn,
            }
        }
    )


@require_GET
def client_ip(request):
    value = request.META.get("HTTP_X_REAL_IP")

    try:
        address = ip_address(value.strip())
    except (AttributeError, ValueError):
        return private_json_response(
            {"error": "client_ip_unavailable"}, status=503
        )

    return private_json_response(
        {
            "ip": str(address),
            "version": address.version,
            "is_public": address.is_global,
        }
    )


@require_GET
def request_headers(request):
    headers = {
        name: request.headers[name]
        for name in REQUEST_HEADER_ALLOWLIST
        if name in request.headers
    }
    return private_json_response({"headers": headers})


def decode_cloudflare_utf8_header(value):
    """Recover UTF-8 Cloudflare header values decoded through WSGI as Latin-1."""
    try:
        return value.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value


@require_GET
def location(request):
    location_data = {
        key: decode_cloudflare_utf8_header(request.headers[header])
        for header, key in CLOUDFLARE_LOCATION_HEADERS
        if header in request.headers
    }
    return private_json_response({"location": location_data})
