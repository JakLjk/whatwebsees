from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path

import maxminddb

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

GEOIP_DATABASE_PATH = Path("/data/geoip/dbip-city-lite.mmdb")

PUBLIC_PAGES = (
    "/",
    "/tools/",
    "/user-agent/",
    "/browser-check/",
    "/screen-resolution/",
    "/http-headers/",
    "/privacy-check/",
    "/webgl/",
    "/canvas-fingerprint/",
)

TOOL_PAGE_METADATA = {
    "tools": {
        "template": "core/tools/index.html",
        "title": "Privacy & Browser Tools | WhatWebSees",
        "description": (
            "Explore privacy-conscious tools for checking your browser, screen, "
            "HTTP headers, privacy signals, WebGL graphics and canvas output."
        ),
        "path": "/tools/",
    },
    "user_agent": {
        "template": "core/tools/user_agent.html",
        "title": "User Agent Checker | WhatWebSees",
        "description": (
            "View your browser's User-Agent, reported platform and available "
            "Client Hints with a private, browser-based checker."
        ),
        "path": "/user-agent/",
    },
    "browser_check": {
        "template": "core/tools/browser_check.html",
        "title": "Browser Checker | WhatWebSees",
        "description": (
            "Check your browser, platform, language, time zone and other "
            "browser-reported details without storing diagnostic values."
        ),
        "path": "/browser-check/",
    },
    "screen_resolution": {
        "template": "core/tools/screen_resolution.html",
        "title": "Screen Resolution Checker | WhatWebSees",
        "description": (
            "Check screen resolution, browser viewport, device pixel ratio, "
            "color depth and orientation locally in your browser."
        ),
        "path": "/screen-resolution/",
    },
    "http_headers": {
        "template": "core/tools/http_headers.html",
        "title": "HTTP Headers Checker | WhatWebSees",
        "description": (
            "See a privacy-conscious selection of HTTP request headers that "
            "reached this website through Cloudflare and its reverse proxy."
        ),
        "path": "/http-headers/",
    },
    "privacy_check": {
        "template": "core/tools/privacy_check.html",
        "title": "Browser Privacy Signals Checker | WhatWebSees",
        "description": (
            "Check browser-reported privacy preferences including Do Not Track, "
            "Global Privacy Control and cookie availability."
        ),
        "path": "/privacy-check/",
    },
    "webgl": {
        "template": "core/tools/webgl.html",
        "title": "WebGL & GPU Checker | WhatWebSees",
        "description": (
            "Inspect browser-reported WebGL support, renderer, vendor and useful "
            "graphics limits without sending GPU details to the server."
        ),
        "path": "/webgl/",
    },
    "canvas_fingerprint": {
        "template": "core/tools/canvas_fingerprint.html",
        "title": "Canvas Fingerprint Test | WhatWebSees",
        "description": (
            "Run an explicit, local canvas rendering test and compare a SHA-256 "
            "hash without uploading or storing the result."
        ),
        "path": "/canvas-fingerprint/",
    },
}


@require_safe
def robots_txt(request):
    content = """User-agent: *
Allow: /

Sitemap: https://whatwebsees.com/sitemap.xml
"""
    return HttpResponse(content, content_type="text/plain; charset=utf-8")


@require_safe
def sitemap_xml(request):
    urls = "\n".join(
        f"  <url>\n    <loc>https://whatwebsees.com{path}</loc>\n  </url>"
        for path in PUBLIC_PAGES
    )
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{urls}\n"
        "</urlset>\n"
    )
    return HttpResponse(content, content_type="application/xml; charset=utf-8")


@require_safe
def home(request):
    return render(request, "core/home.html")


def render_tool_page(request, page):
    metadata = TOOL_PAGE_METADATA[page]
    context = {
        **metadata,
        "canonical_url": f"https://whatwebsees.com{metadata['path']}",
    }
    return render(request, metadata["template"], context)


@require_safe
def tools(request):
    return render_tool_page(request, "tools")


@require_safe
def user_agent(request):
    return render_tool_page(request, "user_agent")


@require_safe
def browser_check(request):
    return render_tool_page(request, "browser_check")


@require_safe
def screen_resolution(request):
    return render_tool_page(request, "screen_resolution")


@require_safe
def http_headers(request):
    return render_tool_page(request, "http_headers")


@require_safe
def privacy_check(request):
    return render_tool_page(request, "privacy_check")


@require_safe
def webgl(request):
    return render_tool_page(request, "webgl")


@require_safe
def canvas_fingerprint(request):
    return render_tool_page(request, "canvas_fingerprint")


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
    asn_value = request.headers.get("X-Visitor-ASN", "").strip()
    organization_value = request.headers.get(
        "X-Visitor-AS-Organization", ""
    ).strip()

    try:
        asn = int(asn_value)
    except ValueError:
        asn = 0

    network_data = {}

    if 1 <= asn <= 4294967295:
        network_data["asn"] = asn

    if organization_value:
        organization = decode_cloudflare_utf8_header(
            organization_value
        ).strip()

        if organization:
            network_data["organization"] = organization[:200]

    return private_json_response({"network": network_data})


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


def has_valid_coordinates(location_data):
    try:
        latitude = float(location_data["latitude"])
        longitude = float(location_data["longitude"])
    except (KeyError, TypeError, ValueError):
        return False

    return -90 <= latitude <= 90 and -180 <= longitude <= 180


@lru_cache(maxsize=1)
def geoip_reader():
    return maxminddb.open_database(str(GEOIP_DATABASE_PATH))


def localized_name(record):
    if not isinstance(record, dict):
        return None

    names = record.get("names")
    if not isinstance(names, dict):
        return None

    name = names.get("en")

    if not isinstance(name, str):
        return None

    name = name.strip()
    return name or None


def dbip_location(address):
    if address is None or not address.is_global:
        return {}

    try:
        record = geoip_reader().get(str(address))
    except Exception:
        # GeoIP is only a fallback. A missing/corrupt database must not
        # make the public location endpoint fail.
        return {}

    if not isinstance(record, dict):
        return {}

    result = {}

    city = localized_name(record.get("city"))
    if city:
        result["city"] = city

    subdivisions = record.get("subdivisions")
    if isinstance(subdivisions, list) and subdivisions:
        region = localized_name(subdivisions[0])
        if region:
            result["region"] = region

    country = record.get("country")
    if isinstance(country, dict):
        country_code = country.get("iso_code")

        if isinstance(country_code, str) and country_code.strip():
            result["country_code"] = country_code.strip()

        country_name = localized_name(country)
        if country_name:
            result["country"] = country_name

    continent = record.get("continent")
    if isinstance(continent, dict):
        continent_code = continent.get("code")

        if isinstance(continent_code, str) and continent_code.strip():
            result["continent_code"] = continent_code.strip()

    geo = record.get("location")
    if isinstance(geo, dict):
        latitude = geo.get("latitude")
        longitude = geo.get("longitude")

        if (
            isinstance(latitude, (int, float))
            and not isinstance(latitude, bool)
            and -90 <= latitude <= 90
            and isinstance(longitude, (int, float))
            and not isinstance(longitude, bool)
            and -180 <= longitude <= 180
        ):
            result["latitude"] = latitude
            result["longitude"] = longitude

        timezone = geo.get("time_zone")
        if isinstance(timezone, str) and timezone.strip():
            result["timezone"] = timezone.strip()

    postal = record.get("postal")
    if isinstance(postal, dict):
        postal_code = postal.get("code")

        if isinstance(postal_code, str) and postal_code.strip():
            result["postal_code"] = postal_code.strip()

    return result


@require_GET
def location(request):
    location_data = {
        key: decode_cloudflare_utf8_header(request.headers[header])
        for header, key in CLOUDFLARE_LOCATION_HEADERS
        if header in request.headers
    }

    # Prefer Cloudflare when it provides a complete coordinate pair.
    # Otherwise use the local DB-IP database as a privacy-friendly fallback.
    if not has_valid_coordinates(location_data):
        value = request.META.get("HTTP_X_REAL_IP")

        try:
            address = ip_address(value.strip())
        except (AttributeError, ValueError):
            address = None

        fallback = dbip_location(address)

        if fallback:
            # Keep useful Cloudflare values and fill only missing metadata.
            for key, value in fallback.items():
                if key not in {"latitude", "longitude"}:
                    if not location_data.get(key):
                        location_data[key] = value

            # Coordinates must always come from one provider as a pair.
            if has_valid_coordinates(fallback):
                location_data["latitude"] = fallback["latitude"]
                location_data["longitude"] = fallback["longitude"]

    return private_json_response({"location": location_data})
