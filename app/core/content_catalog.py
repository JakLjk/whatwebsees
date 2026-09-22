"""Static Learn-section metadata. Article copy remains in versioned templates."""

PUBLISHED = "2026-09-21"

ARTICLES = {
    "what-is-an-ip-address": {
        "title": "What Is an IP Address? IPv4, IPv6, NAT & Privacy | WhatWebSees",
        "description": "Learn how IP addresses route Internet traffic, how IPv4 and IPv6 differ, what NAT does, and what an IP address can and cannot identify.",
        "heading": "What Is an IP Address?",
        "template": "core/learn/what_is_an_ip_address.html",
        "tools": ("ip_lookup", "ip_address_checker", "subnet_calculator"),
        "related": ("how-ip-geolocation-works", "dns-record-types-explained"),
    },
    "how-ip-geolocation-works": {
        "title": "How IP Geolocation Works—and Why It Is Approximate | WhatWebSees",
        "description": "Understand how IP geolocation databases estimate country, region and city, why providers disagree, and why the result is not GPS location.",
        "heading": "How IP Geolocation Works",
        "template": "core/learn/how_ip_geolocation_works.html",
        "tools": ("ip_lookup",),
        "related": ("what-is-an-ip-address", "browser-fingerprinting-explained"),
    },
    "dns-record-types-explained": {
        "title": "DNS Record Types Explained: A, AAAA, MX, TXT & More | WhatWebSees",
        "description": "A practical guide to DNS resolvers, A, AAAA, CNAME, MX, TXT, NS, SOA, PTR records and TTL values with clear examples.",
        "heading": "DNS Record Types Explained",
        "template": "core/learn/dns_record_types_explained.html",
        "tools": ("dns_lookup", "hostname_lookup", "reverse_dns"),
        "related": ("dnssec-explained", "spf-dkim-dmarc-explained"),
    },
    "dnssec-explained": {
        "title": "DNSSEC Explained: Signatures, DNSKEY, DS & Trust | WhatWebSees",
        "description": "Learn how DNSSEC authenticates DNS data with signatures, DNSKEY and DS records, what the chain of trust means, and what DNSSEC does not do.",
        "heading": "DNSSEC Explained",
        "template": "core/learn/dnssec_explained.html",
        "tools": ("dnssec_checker", "dns_lookup"),
        "related": ("dns-record-types-explained", "https-tls-certificates-explained"),
    },
    "spf-dkim-dmarc-explained": {
        "title": "SPF, DKIM and DMARC Explained | WhatWebSees",
        "description": "Understand the distinct roles of SPF, DKIM and DMARC, how their DNS records work together, and why they do not guarantee email delivery.",
        "heading": "SPF, DKIM and DMARC Explained",
        "template": "core/learn/spf_dkim_dmarc_explained.html",
        "tools": ("email_dns_checker", "dns_lookup"),
        "related": ("dns-record-types-explained", "dnssec-explained"),
    },
    "https-tls-certificates-explained": {
        "title": "HTTPS and TLS Certificates Explained | WhatWebSees",
        "description": "Learn how HTTPS, TLS certificates, certificate authorities, hostname validation, SAN, SNI and expiration work together.",
        "heading": "HTTPS and TLS Certificates Explained",
        "template": "core/learn/https_tls_certificates_explained.html",
        "tools": ("ssl_checker", "website_status"),
        "related": ("http-headers-explained", "dnssec-explained"),
    },
    "http-headers-explained": {
        "title": "HTTP Headers Explained: Requests, Responses & Security | WhatWebSees",
        "description": "A clear guide to HTTP request and response headers, content type, caching, compression, CSP, HSTS and referrer policy.",
        "heading": "HTTP Headers Explained",
        "template": "core/learn/http_headers_explained.html",
        "tools": ("http_headers", "server_headers", "security_headers"),
        "related": ("https-tls-certificates-explained", "http-redirects-explained"),
    },
    "browser-fingerprinting-explained": {
        "title": "Browser Fingerprinting Explained | WhatWebSees",
        "description": "Learn how browser attributes, WebGL and canvas may contribute to a fingerprint, how normalization helps, and how fingerprints differ from cookies.",
        "heading": "Browser Fingerprinting Explained",
        "template": "core/learn/browser_fingerprinting_explained.html",
        "tools": ("user_agent", "browser_check", "screen_resolution", "webgl", "canvas_fingerprint", "privacy_check"),
        "related": ("what-is-an-ip-address", "http-headers-explained"),
    },
    "http-redirects-explained": {
        "title": "HTTP Redirects Explained: 301, 302, 303, 307 & 308 | WhatWebSees",
        "description": "Understand HTTP redirect status codes, method handling, redirect chains, HTTPS upgrades, loops and practical user-experience implications.",
        "heading": "HTTP Redirects Explained",
        "template": "core/learn/http_redirects_explained.html",
        "tools": ("redirect_checker", "website_status"),
        "related": ("http-headers-explained", "https-tls-certificates-explained"),
    },
}

LEARN_PATHS = tuple(f"/learn/{slug}/" for slug in ARTICLES)
