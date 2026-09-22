from functools import lru_cache
from ipaddress import ip_address, ip_interface, ip_network
import json
from pathlib import Path
from urllib.parse import urlsplit

import maxminddb

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils.cache import patch_cache_control
from django.views.decorators.http import require_GET, require_http_methods, require_safe

from .batch3_utils import (
    HTML_BODY_LIMIT,
    ROBOTS_BODY_LIMIT,
    SITEMAP_BODY_LIMIT,
    approximate_age,
    decode_body,
    inspect_dnssec,
    inspect_email_dns,
    origin_resource,
    parse_meta_tags,
    parse_robots,
    parse_sitemap,
    rdap_lookup as lookup_rdap,
)
from .content_catalog import ARTICLES, LEARN_PATHS, PUBLISHED
from .dns_utils import DNS_RECORD_TYPES, lookup_records, reverse_lookup
from .network_utils import (
    NetworkToolError,
    check_tls_certificate,
    normalize_domain,
    normalize_http_url,
    resolve_public_host,
    safe_http_request,
)


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

TOOL_PAGE_METADATA = {
    "tools": {
        "template": "core/tools/index.html",
        "title": "Privacy & Browser Tools | WhatWebSees",
        "description": (
            "Explore privacy-conscious IP, DNS, website, browser, security and "
            "calculation tools with useful explanations and no diagnostic history."
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
    "ip_lookup": {
        "template": "core/tools/ip_lookup.html",
        "title": "IP Address Lookup & Geolocation | WhatWebSees",
        "description": "Look up and classify an IPv4 or IPv6 address with approximate location data from a local privacy-conscious GeoIP database.",
        "path": "/ip-lookup/",
    },
    "ip_address_checker": {
        "template": "core/tools/ip_address_checker.html",
        "title": "IP Address Checker & Validator | WhatWebSees",
        "description": "Validate, normalize and explain an IPv4 or IPv6 address, including public, private, loopback and reserved classifications.",
        "path": "/ip-address-checker/",
    },
    "dns_lookup": {
        "template": "core/tools/dns_lookup.html",
        "title": "DNS Lookup for A, MX, TXT & More | WhatWebSees",
        "description": "Query common DNS records for a domain, including A, AAAA, CNAME, MX, NS, TXT and SOA records with TTL values.",
        "path": "/dns-lookup/",
    },
    "reverse_dns": {
        "template": "core/tools/reverse_dns.html",
        "title": "Reverse DNS & PTR Lookup | WhatWebSees",
        "description": "Look up PTR hostnames for a public IPv4 or IPv6 address and understand what reverse DNS records mean.",
        "path": "/reverse-dns/",
    },
    "hostname_lookup": {
        "template": "core/tools/hostname_lookup.html",
        "title": "Hostname to IP Lookup | WhatWebSees",
        "description": "Resolve a public hostname to its deduplicated IPv4 and IPv6 addresses with a simple privacy-conscious lookup.",
        "path": "/hostname-lookup/",
    },
    "ssl_checker": {
        "template": "core/tools/ssl_checker.html",
        "title": "SSL Certificate Checker | WhatWebSees",
        "description": "Validate a public website's TLS certificate on port 443 and inspect its issuer, names, dates, protocol and cipher.",
        "path": "/ssl-checker/",
    },
    "website_status": {
        "template": "core/tools/website_status.html",
        "title": "Website Status & Response Time Checker | WhatWebSees",
        "description": "Check a public website's HTTP status, response time, redirects, final URL and content type using bounded safe requests.",
        "path": "/website-status/",
    },
    "server_headers": {
        "template": "core/tools/server_headers.html",
        "title": "Server Response Headers Checker | WhatWebSees",
        "description": "Inspect a safe selection of HTTP response and security headers returned by a public website without exposing cookies.",
        "path": "/server-headers/",
    },
    "subnet_calculator": {
        "template": "core/tools/subnet_calculator.html",
        "title": "Subnet & CIDR Calculator | WhatWebSees",
        "description": "Calculate IPv4 or IPv6 CIDR network boundaries, masks, address counts and correct /31 and /32 host semantics.",
        "path": "/subnet-calculator/",
    },
    "password_strength": {
        "template": "core/tools/password_strength.html",
        "title": "Private Password Strength Checker | WhatWebSees",
        "description": "Check password length and useful strength signals entirely in your browser without transmitting or storing the password.",
        "path": "/password-strength/",
    },
    "punycode_converter": {
        "template": "core/tools/punycode_converter.html",
        "title": "Punycode & IDN Domain Converter | WhatWebSees",
        "description": "Convert Unicode internationalized domain names to ASCII Punycode and decode Punycode domains without a network lookup.",
        "path": "/punycode-converter/",
    },
    "download_time_calculator": {
        "template": "core/tools/download_time_calculator.html",
        "title": "Download Time Calculator | WhatWebSees",
        "description": "Estimate ideal file download time from file size and connection speed with clear decimal unit conversions.",
        "path": "/download-time-calculator/",
    },
    "dnssec_checker": {
        "template": "core/tools/dnssec_checker.html",
        "title": "DNSSEC Checker: Inspect DNSKEY & DS Records | WhatWebSees",
        "description": "Inspect DNSKEY and DS records for a domain and understand whether DNSSEC-related records and a parent delegation are observable.",
        "path": "/dnssec-checker/",
    },
    "email_dns_checker": {
        "template": "core/tools/email_dns_checker.html",
        "title": "Email DNS Checker for MX, SPF, DKIM & DMARC | WhatWebSees",
        "description": "Inspect a domain's mail routing and published MX, SPF, DMARC and optional DKIM selector records without contacting a mail server.",
        "path": "/email-dns-checker/",
    },
    "redirect_checker": {
        "template": "core/tools/redirect_checker.html",
        "title": "HTTP Redirect Checker & Chain Inspector | WhatWebSees",
        "description": "Follow a public HTTP or HTTPS redirect chain safely and inspect every URL, status, Location target, timing and final destination.",
        "path": "/redirect-checker/",
    },
    "security_headers": {
        "template": "core/tools/security_headers.html",
        "title": "HTTP Security Headers Checker | WhatWebSees",
        "description": "Inspect CSP, HSTS, Referrer-Policy, Permissions-Policy and cross-origin response headers without assigning a misleading grade.",
        "path": "/security-headers/",
    },
    "robots_txt_checker": {
        "template": "core/tools/robots_txt_checker.html",
        "title": "Robots.txt Checker & Directive Inspector | WhatWebSees",
        "description": "Safely retrieve a site's bounded robots.txt file and inspect its user-agent groups and Sitemap directives.",
        "path": "/robots-txt-checker/",
    },
    "sitemap_checker": {
        "template": "core/tools/sitemap_checker.html",
        "title": "XML Sitemap Checker for URL Sets & Indexes | WhatWebSees",
        "description": "Safely inspect one bounded XML sitemap, identify urlset or sitemapindex documents, and review entry counts, URLs and lastmod values.",
        "path": "/sitemap-checker/",
    },
    "meta_tags_checker": {
        "template": "core/tools/meta_tags_checker.html",
        "title": "Meta Tag Checker for SEO & Social Metadata | WhatWebSees",
        "description": "Inspect server-delivered title, description, canonical, robots, Open Graph and Twitter metadata from a public web page.",
        "path": "/meta-tags-checker/",
    },
    "url_parser": {
        "template": "core/tools/url_parser.html",
        "title": "Private URL Parser & Analyzer | WhatWebSees",
        "description": "Parse a URL into its scheme, hostname, port, path, query, fragment and parameters entirely in your browser without requesting it.",
        "path": "/url-parser/",
    },
    "file_hash": {
        "template": "core/tools/file_hash.html",
        "title": "Private File Hash Calculator: SHA-256, SHA-384, SHA-512 | WhatWebSees",
        "description": "Calculate SHA-256, SHA-384 and SHA-512 hashes locally with Web Crypto; your file, filename and hashes never leave the browser.",
        "path": "/file-hash/",
    },
    "rdap_lookup": {
        "template": "core/tools/rdap_lookup.html",
        "title": "Domain RDAP Lookup: Registration & Registry Data | WhatWebSees",
        "description": "Look up public domain registration dates, status, registrar, nameservers and source through the IANA-discovered HTTPS RDAP service.",
        "path": "/rdap-lookup/",
    },
    "domain_age": {
        "template": "core/tools/domain_age.html",
        "title": "Domain Age Checker Using Registry RDAP Data | WhatWebSees",
        "description": "Estimate a domain's age from its registry-reported RDAP creation date and review expiration and update dates where available.",
        "path": "/domain-age/",
    },
}

TOOL_NAMES = {
    "user_agent": "User Agent Checker",
    "browser_check": "Browser Checker",
    "screen_resolution": "Screen Resolution Checker",
    "http_headers": "HTTP Headers Checker",
    "privacy_check": "Browser Privacy Signals",
    "webgl": "WebGL & GPU Checker",
    "canvas_fingerprint": "Canvas Fingerprint Test",
    "ip_lookup": "IP Address Lookup",
    "ip_address_checker": "IP Address Checker",
    "dns_lookup": "DNS Lookup",
    "reverse_dns": "Reverse DNS Lookup",
    "hostname_lookup": "Hostname Lookup",
    "ssl_checker": "SSL Certificate Checker",
    "website_status": "Website Status",
    "server_headers": "Server Headers Checker",
    "subnet_calculator": "Subnet / CIDR Calculator",
    "password_strength": "Password Strength Checker",
    "punycode_converter": "Punycode Converter",
    "download_time_calculator": "Download Time Calculator",
    "dnssec_checker": "DNSSEC Checker",
    "email_dns_checker": "Email DNS Checker",
    "redirect_checker": "Redirect Checker",
    "security_headers": "Security Headers Checker",
    "robots_txt_checker": "Robots.txt Checker",
    "sitemap_checker": "Sitemap Checker",
    "meta_tags_checker": "Meta Tag Checker",
    "url_parser": "URL Parser & Analyzer",
    "file_hash": "File Hash Calculator",
    "rdap_lookup": "Domain RDAP Lookup",
    "domain_age": "Domain Age Checker",
}

TOOL_GROUPS = (
    ("IP & Network", ("ip_lookup", "ip_address_checker", "dns_lookup", "dnssec_checker", "reverse_dns", "hostname_lookup", "subnet_calculator", "rdap_lookup", "domain_age")),
    ("Browser & Device", ("user_agent", "browser_check", "screen_resolution", "privacy_check", "webgl", "canvas_fingerprint")),
    ("Website Diagnostics", ("website_status", "redirect_checker", "ssl_checker", "server_headers", "security_headers", "http_headers", "robots_txt_checker", "sitemap_checker", "meta_tags_checker")),
    ("Security & Utilities", ("email_dns_checker", "password_strength", "punycode_converter", "url_parser", "file_hash", "download_time_calculator")),
)

RELATED_TOOLS = {
    "user_agent": ("browser_check", "privacy_check", "http_headers"),
    "browser_check": ("user_agent", "screen_resolution", "privacy_check"),
    "screen_resolution": ("browser_check", "webgl", "canvas_fingerprint"),
    "http_headers": ("server_headers", "user_agent", "privacy_check"),
    "privacy_check": ("password_strength", "browser_check", "user_agent"),
    "webgl": ("browser_check", "screen_resolution", "canvas_fingerprint"),
    "canvas_fingerprint": ("webgl", "privacy_check", "browser_check"),
    "ip_lookup": ("ip_address_checker", "dns_lookup", "reverse_dns", "hostname_lookup"),
    "ip_address_checker": ("ip_lookup", "subnet_calculator", "reverse_dns"),
    "dns_lookup": ("hostname_lookup", "reverse_dns", "ssl_checker", "ip_lookup"),
    "reverse_dns": ("ip_lookup", "dns_lookup", "hostname_lookup"),
    "hostname_lookup": ("dns_lookup", "reverse_dns", "ssl_checker"),
    "ssl_checker": ("website_status", "server_headers", "dns_lookup"),
    "website_status": ("ssl_checker", "server_headers", "dns_lookup"),
    "server_headers": ("website_status", "ssl_checker", "http_headers"),
    "subnet_calculator": ("ip_address_checker", "ip_lookup", "hostname_lookup"),
    "password_strength": ("privacy_check", "browser_check", "punycode_converter"),
    "punycode_converter": ("dns_lookup", "hostname_lookup", "ssl_checker"),
    "download_time_calculator": ("website_status", "browser_check", "screen_resolution"),
    "dnssec_checker": ("dns_lookup", "email_dns_checker", "hostname_lookup"),
    "email_dns_checker": ("dns_lookup", "dnssec_checker", "rdap_lookup"),
    "redirect_checker": ("website_status", "security_headers", "ssl_checker"),
    "security_headers": ("server_headers", "ssl_checker", "http_headers"),
    "robots_txt_checker": ("sitemap_checker", "meta_tags_checker", "website_status"),
    "sitemap_checker": ("robots_txt_checker", "meta_tags_checker", "website_status"),
    "meta_tags_checker": ("sitemap_checker", "robots_txt_checker", "redirect_checker"),
    "url_parser": ("punycode_converter", "redirect_checker", "dns_lookup"),
    "file_hash": ("password_strength", "privacy_check", "url_parser"),
    "rdap_lookup": ("domain_age", "dns_lookup", "hostname_lookup"),
    "domain_age": ("rdap_lookup", "dns_lookup", "ssl_checker"),
}

RELATED_LEARN = {
    "ip_lookup": ("how-ip-geolocation-works", "what-is-an-ip-address"),
    "ip_address_checker": ("what-is-an-ip-address",),
    "subnet_calculator": ("what-is-an-ip-address",),
    "dns_lookup": ("dns-record-types-explained", "dnssec-explained"),
    "dnssec_checker": ("dnssec-explained", "dns-record-types-explained"),
    "email_dns_checker": ("spf-dkim-dmarc-explained", "dns-record-types-explained"),
    "ssl_checker": ("https-tls-certificates-explained",),
    "website_status": ("http-redirects-explained", "https-tls-certificates-explained"),
    "redirect_checker": ("http-redirects-explained",),
    "http_headers": ("http-headers-explained", "browser-fingerprinting-explained"),
    "server_headers": ("http-headers-explained",),
    "security_headers": ("http-headers-explained", "https-tls-certificates-explained"),
    "user_agent": ("browser-fingerprinting-explained",),
    "browser_check": ("browser-fingerprinting-explained",),
    "screen_resolution": ("browser-fingerprinting-explained",),
    "webgl": ("browser-fingerprinting-explained",),
    "canvas_fingerprint": ("browser-fingerprinting-explained",),
    "privacy_check": ("browser-fingerprinting-explained",),
}

RESULT_GUIDANCE = {
    "user_agent": "The values are browser claims used for compatibility, not proof of a device or person. Browser updates, reduction policies, extensions and overrides can change them.",
    "browser_check": "These fields describe what this browser exposes in this session. They can help troubleshoot compatibility, but they are not a stable identity and may change with settings, updates or privacy protections.",
    "screen_resolution": "Screen, available area and viewport are different measurements. Resizing, zoom, display scaling, orientation and attaching another monitor can legitimately change the result.",
    "http_headers": "This is an allowlisted view of headers received by WhatWebSees, not every byte on the connection. Proxies and browser policy can add, remove or reduce values.",
    "privacy_check": "GPC and DNT communicate preferences; they do not technically block tracking on their own. Cookie availability and online status are browser state, not a complete privacy audit.",
    "webgl": "Renderer and capability values describe the current graphics path. Generic, software-rendered or reduced values are normal under privacy defenses, virtual machines and some drivers.",
    "canvas_fingerprint": "A matching hash means this particular drawing produced the same pixels in those runs. It is not personal identification, and many browsers may share a hash while one browser can change over time.",
    "ip_lookup": "Address classification is deterministic for the submitted value; geographic fields are database estimates. A result may identify an ISP gateway or VPN exit and should never be treated as GPS or a person’s address.",
    "ip_address_checker": "A valid address can still be private, loopback, link-local, multicast or reserved. Globally routable means suitable for public routing, not that the address is reachable or trustworthy.",
    "dns_lookup": "The answer shows records returned through this resolver and their current TTL. Caching, traffic steering and recent zone changes can make another resolver or later query differ.",
    "reverse_dns": "A PTR name is optional metadata controlled by the address-range operator. It can aid diagnostics and mail configuration, but it does not authenticate the service using the address.",
    "hostname_lookup": "These are the current public address candidates returned to this resolver. Multiple answers are normal for redundancy or traffic steering; an address answer does not prove an application is listening.",
    "ssl_checker": "A valid result means the presented chain, hostname and dates passed this environment’s checks now. It does not certify the site’s content; days remaining are renewal context rather than a security score.",
    "website_status": "The status family describes this one HTTP transaction: 2xx success, 3xx redirection, 4xx client/request conditions and 5xx server failures. Timing is a server-side snapshot, not page-load performance.",
    "server_headers": "Headers are clues about this response, not a full security audit. Values can vary by URL, CDN edge, method and negotiation, and a present policy can still be poorly configured.",
    "subnet_calculator": "The boundaries are mathematical results for the prefix. Traditional IPv4 usable-host rules have /31 and /32 exceptions, while IPv6 has no broadcast address and assignment policy determines actual use.",
    "password_strength": "This local heuristic highlights length and simple patterns. It cannot know whether a password is reused, exposed elsewhere or targeted, and its label is not a guarantee against guessing.",
    "punycode_converter": "The two values are alternate representations of the same IDN label under the platform codec. Conversion does not check registration, ownership, DNS existence or look-alike safety.",
    "download_time_calculator": "The estimate divides file size by an idealized bit rate. Protocol overhead, congestion, Wi-Fi conditions, server limits and changing throughput normally make real downloads slower or variable.",
}

PUBLIC_PAGES = (("/",) + tuple(metadata["path"] for metadata in TOOL_PAGE_METADATA.values())
                + ("/learn/",) + LEARN_PATHS + ("/glossary/",))


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


def _tool_link(page):
    return {
        "name": TOOL_NAMES[page],
        "path": TOOL_PAGE_METADATA[page]["path"],
        "description": TOOL_PAGE_METADATA[page]["description"],
    }


def render_tool_page(request, page, extra_context=None):
    metadata = TOOL_PAGE_METADATA[page]
    breadcrumb_items = [
        {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://whatwebsees.com/"},
        {"@type": "ListItem", "position": 2, "name": "Tools", "item": "https://whatwebsees.com/tools/"},
    ]
    if page != "tools":
        breadcrumb_items.append(
            {
                "@type": "ListItem",
                "position": 3,
                "name": TOOL_NAMES[page],
                "item": f"https://whatwebsees.com{metadata['path']}",
            }
        )
    context = {
        **metadata,
        "canonical_url": f"https://whatwebsees.com{metadata['path']}",
        "breadcrumb_json": json.dumps(
            {"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": breadcrumb_items}
        ),
        "related_tools": [_tool_link(key) for key in RELATED_TOOLS.get(page, ())],
        "related_learn": [
            {"heading": ARTICLES[slug]["heading"], "path": f"/learn/{slug}/"}
            for slug in RELATED_LEARN.get(page, ())
        ],
        "result_guidance": RESULT_GUIDANCE.get(page),
    }
    if extra_context:
        context.update(extra_context)
    response = render(request, metadata["template"], context)
    if request.method == "POST":
        patch_cache_control(response, private=True, no_store=True)
    return response


@require_safe
def tools(request):
    groups = [
        {"name": name, "tools": [_tool_link(key) for key in keys]}
        for name, keys in TOOL_GROUPS
    ]
    return render_tool_page(request, "tools", {"tool_groups": groups})


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


def _submitted_value(request, name, maximum=2048):
    return request.POST.get(name, "").strip()[:maximum] if request.method == "POST" else ""


def _ip_details(address):
    mapped = getattr(address, "ipv4_mapped", None)
    flags = (
        ("Globally routable", address.is_global),
        ("Private", address.is_private),
        ("Loopback", address.is_loopback),
        ("Link-local", address.is_link_local),
        ("Multicast", address.is_multicast),
        ("Reserved", address.is_reserved),
        ("Unspecified", address.is_unspecified),
    )
    return {
        "normalized": str(address),
        "expanded": address.exploded,
        "version": address.version,
        "flags": flags,
        "mapped_ipv4": str(mapped) if mapped is not None else None,
    }


@require_http_methods(["GET", "POST"])
def ip_lookup(request):
    value = _submitted_value(request, "ip", 200)
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            address = ip_address(value)
            context["result"] = _ip_details(address)
            context["location"] = dbip_location(address) if address.is_global else {}
        except ValueError:
            context["error"] = "Enter a valid IPv4 or IPv6 address."
    return render_tool_page(request, "ip_lookup", context)


@require_http_methods(["GET", "POST"])
def ip_address_checker(request):
    value = _submitted_value(request, "ip", 200)
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            context["result"] = _ip_details(ip_address(value))
        except ValueError:
            context["error"] = "This is not a valid IPv4 or IPv6 address."
    return render_tool_page(request, "ip_address_checker", context)


@require_http_methods(["GET", "POST"])
def dns_lookup(request):
    value = _submitted_value(request, "domain", 253)
    record_type = request.POST.get("record_type", "A").upper() if request.method == "POST" else "A"
    context = {
        "submitted_value": value,
        "record_type": record_type,
        "record_types": ("ALL",) + DNS_RECORD_TYPES,
    }
    if request.method == "POST":
        try:
            domain, records = lookup_records(value, record_type)
            context.update({"queried_domain": domain, "records": records})
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "dns_lookup", context)


@require_http_methods(["GET", "POST"])
def reverse_dns(request):
    value = _submitted_value(request, "ip", 200)
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            address, hostnames = reverse_lookup(value)
            context.update({"queried_ip": address, "hostnames": hostnames})
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "reverse_dns", context)


@require_http_methods(["GET", "POST"])
def hostname_lookup(request):
    value = _submitted_value(request, "hostname", 253)
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            hostname = normalize_domain(value)
            target = resolve_public_host(hostname, 443)
            context.update(
                {
                    "queried_hostname": target.hostname,
                    "ipv4_addresses": tuple(address for address in target.addresses if ip_address(address).version == 4),
                    "ipv6_addresses": tuple(address for address in target.addresses if ip_address(address).version == 6),
                }
            )
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "hostname_lookup", context)


@require_http_methods(["GET", "POST"])
def ssl_checker(request):
    value = _submitted_value(request, "hostname", 253)
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            context["result"] = check_tls_certificate(value)
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "ssl_checker", context)


@require_http_methods(["GET", "POST"])
def website_status(request):
    value = _submitted_value(request, "url")
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            normalized_url = normalize_http_url(value)
            result = safe_http_request(normalized_url)
            context.update(
                {
                    "result": result,
                    "normalized_url": normalized_url,
                    "content_type": result.headers.get("content-type", "Not returned"),
                    "is_https": result.url.startswith("https://"),
                }
            )
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "website_status", context)


SERVER_HEADER_ALLOWLIST = (
    ("server", "Server"),
    ("content-type", "Content-Type"),
    ("content-length", "Content-Length"),
    ("cache-control", "Cache-Control"),
    ("content-encoding", "Content-Encoding"),
    ("strict-transport-security", "Strict-Transport-Security"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("location", "Location"),
)


@require_http_methods(["GET", "POST"])
def server_headers(request):
    value = _submitted_value(request, "url")
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            result = safe_http_request(value)
            selected = tuple(
                (display_name, result.headers[lower_name])
                for lower_name, display_name in SERVER_HEADER_ALLOWLIST
                if lower_name in result.headers
            )
            context.update({"result": result, "selected_headers": selected})
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "server_headers", context)


@require_http_methods(["GET", "POST"])
def subnet_calculator(request):
    value = _submitted_value(request, "cidr", 200)
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            interface = ip_interface(value)
            network = ip_network(value, strict=False)
            result = {
                "input_address": str(interface.ip),
                "network": str(network.network_address),
                "prefix": network.prefixlen,
                "netmask": str(network.netmask),
                "total": network.num_addresses,
                "first": str(network.network_address),
                "last": str(network.broadcast_address),
                "version": network.version,
            }
            if network.version == 4:
                result["broadcast"] = str(network.broadcast_address)
                if network.prefixlen == 32:
                    result.update({"usable": 1, "first_usable": str(network.network_address), "last_usable": str(network.network_address), "host_note": "A /32 represents one host address."})
                elif network.prefixlen == 31:
                    result.update({"usable": 2, "first_usable": str(network.network_address), "last_usable": str(network.broadcast_address), "host_note": "Both addresses can be used on an RFC 3021 point-to-point link."})
                else:
                    result.update({"usable": network.num_addresses - 2, "first_usable": str(network.network_address + 1), "last_usable": str(network.broadcast_address - 1), "host_note": "Traditional IPv4 host count excludes the network and broadcast addresses."})
            else:
                result["host_note"] = "IPv6 has no broadcast address; address assignment depends on subnet policy."
            context["result"] = result
        except ValueError:
            context["error"] = "Enter an IPv4 or IPv6 address with a CIDR prefix, such as 192.168.1.50/24."
    return render_tool_page(request, "subnet_calculator", context)


@require_safe
def password_strength(request):
    return render_tool_page(request, "password_strength")


@require_http_methods(["GET", "POST"])
def punycode_converter(request):
    value = _submitted_value(request, "domain", 253)
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            candidate = value.strip().rstrip(".")
            if (
                not candidate
                or any(ord(character) < 33 for character in candidate)
                or any(character in candidate for character in "/\\@:#?%[]")
            ):
                raise UnicodeError
            ascii_domain = candidate.encode("idna").decode("ascii").lower()
            labels = ascii_domain.split(".")
            if len(labels) < 2 or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(character.isalnum() or character == "-" for character in label)
                for label in labels
            ):
                raise UnicodeError
            unicode_domain = ascii_domain.encode("ascii").decode("idna")
            context["result"] = {"ascii": ascii_domain, "unicode": unicode_domain}
        except (NetworkToolError, UnicodeError) as error:
            context["error"] = getattr(
                error,
                "message",
                "The domain could not be converted with the platform IDNA implementation.",
            )
    return render_tool_page(request, "punycode_converter", context)


@require_safe
def download_time_calculator(request):
    return render_tool_page(request, "download_time_calculator")


@require_http_methods(["GET", "POST"])
def dnssec_checker(request):
    value = _submitted_value(request, "domain", 253)
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            context["result"] = inspect_dnssec(value)
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "dnssec_checker", context)


@require_http_methods(["GET", "POST"])
def email_dns_checker(request):
    value = _submitted_value(request, "domain", 253)
    selector = _submitted_value(request, "selector", 63)
    context = {"submitted_value": value, "selector": selector}
    if request.method == "POST":
        try:
            context["result"] = inspect_email_dns(value, selector)
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "email_dns_checker", context)


@require_http_methods(["GET", "POST"])
def redirect_checker(request):
    value = _submitted_value(request, "url")
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            result = safe_http_request(value)
            context.update({"result": result, "is_https": result.url.startswith("https://")})
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "redirect_checker", context)


SECURITY_HEADERS = (
    ("strict-transport-security", "Strict-Transport-Security"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
    ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
)


@require_http_methods(["GET", "POST"])
def security_headers(request):
    value = _submitted_value(request, "url")
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            result = safe_http_request(value)
            context.update({
                "result": result,
                "header_results": tuple(
                    {"name": label, "present": key in result.headers, "value": result.headers.get(key, "")}
                    for key, label in SECURITY_HEADERS
                ),
            })
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "security_headers", context)


@require_http_methods(["GET", "POST"])
def robots_txt_checker(request):
    value = _submitted_value(request, "url")
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            target = origin_resource(value, "/robots.txt")
            result = safe_http_request(target, fetch_body=True, max_body=ROBOTS_BODY_LIMIT)
            context.update({"result": result, "target_url": target, "exists": result.status == 200})
            if result.status == 200:
                text = decode_body(result, (("text/plain", "+text"), ("text/html", "+html"), ("application/octet-stream", "+octet-stream")))
                sitemaps, agents = parse_robots(text)
                context.update({"robots_text": text, "sitemaps": sitemaps, "agents": agents})
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "robots_txt_checker", context)


def _sitemap_target(value):
    normalized = normalize_http_url(value)
    parsed = urlsplit(normalized)
    if parsed.path in {"", "/"}:
        return origin_resource(normalized, "/sitemap.xml")
    if not parsed.path.lower().endswith(".xml"):
        raise NetworkToolError("invalid_sitemap_url", "Enter a site origin or an explicit .xml sitemap URL.")
    return normalized


@require_http_methods(["GET", "POST"])
def sitemap_checker(request):
    value = _submitted_value(request, "url")
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            target = _sitemap_target(value)
            result = safe_http_request(target, fetch_body=True, max_body=SITEMAP_BODY_LIMIT)
            context.update({"result": result, "target_url": target})
            if result.status == 200:
                text = decode_body(result, (("application/xml", "+xml"), ("text/xml", "+xml"), ("text/plain", "+plain")))
                context["sitemap"] = parse_sitemap(text)
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "sitemap_checker", context)


@require_http_methods(["GET", "POST"])
def meta_tags_checker(request):
    value = _submitted_value(request, "url")
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            result = safe_http_request(value, fetch_body=True, max_body=HTML_BODY_LIMIT)
            context["result"] = result
            if result.status == 200:
                text = decode_body(result, (("text/html", "+html"), ("application/xhtml+xml", "+xml")))
                context["metadata"] = parse_meta_tags(text)
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "meta_tags_checker", context)


@require_safe
def url_parser(request):
    return render_tool_page(request, "url_parser")


@require_safe
def file_hash(request):
    return render_tool_page(request, "file_hash")


@require_http_methods(["GET", "POST"])
def rdap_lookup(request):
    value = _submitted_value(request, "domain", 253)
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            context["result"] = lookup_rdap(value)
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "rdap_lookup", context)


@require_http_methods(["GET", "POST"])
def domain_age(request):
    value = _submitted_value(request, "domain", 253)
    context = {"submitted_value": value}
    if request.method == "POST":
        try:
            result = lookup_rdap(value)
            context.update({"result": result, "age": approximate_age(result.get("created"))})
        except NetworkToolError as error:
            context.update({"error": error.message, "error_code": error.code})
    return render_tool_page(request, "domain_age", context)


@require_safe
def learn(request):
    articles = [
        {**metadata, "path": f"/learn/{slug}/"}
        for slug, metadata in ARTICLES.items()
    ]
    breadcrumb = {"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": [
        {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://whatwebsees.com/"},
        {"@type": "ListItem", "position": 2, "name": "Learn", "item": "https://whatwebsees.com/learn/"},
    ]}
    return render(request, "core/learn/index.html", {
        "title": "Learn About Web, Network & Browser Privacy | WhatWebSees",
        "description": "Evergreen guides to IP addresses, DNS, email authentication, TLS, HTTP headers, redirects and browser fingerprinting.",
        "canonical_url": "https://whatwebsees.com/learn/",
        "articles": articles,
        "breadcrumb_json": json.dumps(breadcrumb),
    })


@require_safe
def learn_article(request, slug):
    metadata = ARTICLES.get(slug)
    if metadata is None:
        from django.http import Http404
        raise Http404
    path = f"/learn/{slug}/"
    breadcrumb = {
        "@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": [
            {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://whatwebsees.com/"},
            {"@type": "ListItem", "position": 2, "name": "Learn", "item": "https://whatwebsees.com/learn/"},
            {"@type": "ListItem", "position": 3, "name": metadata["heading"], "item": f"https://whatwebsees.com{path}"},
        ],
    }
    article_json = {
        "@context": "https://schema.org", "@type": "Article", "headline": metadata["heading"],
        "datePublished": PUBLISHED, "dateModified": PUBLISHED,
        "author": {"@type": "Organization", "name": "WhatWebSees"},
        "publisher": {"@type": "Organization", "name": "WhatWebSees"},
        "mainEntityOfPage": f"https://whatwebsees.com{path}",
    }
    related_articles = [
        {"heading": ARTICLES[item]["heading"], "path": f"/learn/{item}/"}
        for item in metadata["related"]
    ]
    return render(request, metadata["template"], {
        **metadata, "canonical_url": f"https://whatwebsees.com{path}",
        "published": PUBLISHED, "breadcrumb_json": json.dumps(breadcrumb),
        "article_json": json.dumps(article_json),
        "article_tools": [_tool_link(item) for item in metadata["tools"]],
        "related_articles": related_articles,
    })


@require_safe
def glossary(request):
    breadcrumb = {"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": [
        {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://whatwebsees.com/"},
        {"@type": "ListItem", "position": 2, "name": "Learn", "item": "https://whatwebsees.com/learn/"},
        {"@type": "ListItem", "position": 3, "name": "Glossary", "item": "https://whatwebsees.com/glossary/"},
    ]}
    return render(request, "core/learn/glossary.html", {
        "title": "Web, DNS, Network & Privacy Glossary | WhatWebSees",
        "description": "Clear definitions for IP, DNS, email authentication, HTTP, TLS, browser privacy, subnetting, Punycode and RDAP terms.",
        "canonical_url": "https://whatwebsees.com/glossary/",
        "breadcrumb_json": json.dumps(breadcrumb),
    })


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


@require_GET
def favicon(request):
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<rect width="64" height="64" rx="15" fill="#2f5edb"/>
<text x="32" y="43" text-anchor="middle"
      font-family="Arial,Helvetica,sans-serif"
      font-size="38" font-weight="700" fill="white">W</text>
</svg>"""
    response = HttpResponse(svg, content_type="image/svg+xml; charset=utf-8")
    response["Cache-Control"] = "public, max-age=604800"
    return response
