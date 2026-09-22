"""Bounded parsers and DNS/RDAP helpers for the Batch 3 diagnostics."""

from datetime import datetime, timezone
from functools import lru_cache
from html.parser import HTMLParser
import json
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

import dns.dnssec
import dns.exception
import dns.resolver

from .dns_utils import _resolver
from .network_utils import NetworkToolError, normalize_domain, normalize_http_url, safe_http_request


ROBOTS_BODY_LIMIT = 64 * 1024
SITEMAP_BODY_LIMIT = 512 * 1024
HTML_BODY_LIMIT = 256 * 1024
RDAP_BODY_LIMIT = 768 * 1024
IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"


def _answer(name, record_type):
    try:
        return _resolver().resolve(
            name, record_type, raise_on_no_answer=False, search=False
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as error:
        raise NetworkToolError("timeout", "The DNS query timed out. Try again shortly.") from error
    except dns.resolver.NoNameservers as error:
        raise NetworkToolError("resolver_unavailable", "No DNS resolver could answer the query.") from error
    except dns.exception.DNSException as error:
        raise NetworkToolError("dns_error", "The DNS query could not be completed.") from error


def _values(answer, *, limit=100):
    if answer is None or answer.rrset is None:
        return ()
    return tuple(item.to_text()[:4096] for item in answer)[:limit]


def inspect_dnssec(value):
    domain = normalize_domain(value)
    dnskey_answer = _answer(domain, "DNSKEY")
    ds_answer = _answer(domain, "DS")
    dnskeys = []
    if dnskey_answer is not None and dnskey_answer.rrset is not None:
        for key in dnskey_answer:
            dnskeys.append(
                {
                    "text": key.to_text()[:4096],
                    "key_tag": dns.dnssec.key_id(key),
                    "flags": getattr(key, "flags", None),
                    "algorithm": getattr(key, "algorithm", None),
                }
            )
    ds_records = _values(ds_answer)
    if dnskeys and ds_records:
        interpretation = "DNSKEY and parent-side DS records were observed, which is consistent with a DNSSEC delegation. This is not a full cryptographic chain validation."
    elif dnskeys:
        interpretation = "DNSKEY records were observed, but no DS record was returned for the delegation. The zone may be signed without a parent chain of trust."
    elif ds_records:
        interpretation = "A DS delegation was observed, but this resolver did not return DNSKEY records for the zone. The configuration may be incomplete or temporarily unavailable."
    else:
        interpretation = "No DNSKEY or DS records were observed. This lookup did not find evidence of a DNSSEC-signed delegation."
    return {
        "domain": domain,
        "dnskeys": tuple(dnskeys),
        "ds_records": ds_records,
        "has_dnskey": bool(dnskeys),
        "has_ds": bool(ds_records),
        "interpretation": interpretation,
    }


def _txt_value(record):
    strings = getattr(record, "strings", None)
    if strings is not None:
        return b"".join(strings).decode("utf-8", "replace")[:4096]
    text = record.to_text()
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1].replace('" "', "")
    return text[:4096]


def _txt_records(name):
    answer = _answer(name, "TXT")
    if answer is None or answer.rrset is None:
        return ()
    return tuple(_txt_value(item) for item in answer)[:100]


def inspect_email_dns(value, selector=""):
    domain = normalize_domain(value)
    selector = selector.strip()
    if selector:
        if len(selector) > 63 or not all(character.isalnum() or character in "-_" for character in selector):
            raise NetworkToolError("invalid_selector", "The DKIM selector may contain letters, numbers, hyphens and underscores.")
    mx_records = _values(_answer(domain, "MX"))
    spf_records = tuple(item for item in _txt_records(domain) if item.lower().startswith("v=spf1"))
    dmarc_records = tuple(item for item in _txt_records(f"_dmarc.{domain}") if item.lower().startswith("v=dmarc1"))
    dmarc_policy = None
    if dmarc_records:
        for part in dmarc_records[0].split(";"):
            key, separator, policy = part.strip().partition("=")
            if separator and key.lower() == "p":
                dmarc_policy = policy.strip().lower()[:30]
                break
    dkim_records = ()
    if selector:
        dkim_records = tuple(
            item for item in _txt_records(f"{selector}._domainkey.{domain}")
            if item.lower().startswith("v=dkim1") or "p=" in item.lower()
        )
    return {
        "domain": domain,
        "mx_records": mx_records,
        "spf_records": spf_records,
        "dmarc_records": dmarc_records,
        "dmarc_policy": dmarc_policy,
        "selector": selector,
        "dkim_records": dkim_records,
    }


def origin_resource(value, resource_path):
    normalized = normalize_http_url(value)
    parsed = urlsplit(normalized)
    return urlunsplit((parsed.scheme, parsed.netloc, resource_path, "", ""))


def decode_body(result, allowed_types):
    content_type = result.headers.get("content-type", "").lower()
    media_type = content_type.split(";", 1)[0].strip()
    if media_type and not any(media_type == allowed or media_type.endswith(suffix) for allowed, suffix in allowed_types):
        raise NetworkToolError("unsupported_content", "The server returned a content type this checker does not inspect.")
    charset = "utf-8"
    for part in content_type.split(";")[1:]:
        key, separator, value = part.strip().partition("=")
        if separator and key.lower() == "charset":
            charset = value.strip(' "')[:40]
    try:
        return result.body.decode(charset, "replace")
    except LookupError:
        return result.body.decode("utf-8", "replace")


def parse_robots(text):
    sitemaps = []
    agents = []
    for raw_line in text.splitlines()[:5000]:
        line = raw_line.split("#", 1)[0].strip()
        key, separator, value = line.partition(":")
        if not separator or not value.strip():
            continue
        if key.strip().lower() == "sitemap":
            sitemaps.append(value.strip()[:2048])
        elif key.strip().lower() == "user-agent":
            agents.append(value.strip()[:200])
    return tuple(dict.fromkeys(sitemaps))[:100], tuple(dict.fromkeys(agents))[:100]


def parse_sitemap(text):
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise NetworkToolError("invalid_xml", "Sitemaps containing DTD or entity declarations are not accepted.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise NetworkToolError("invalid_xml", "The response was not a well-formed XML sitemap.") from error
    kind = root.tag.rsplit("}", 1)[-1]
    if kind not in {"urlset", "sitemapindex"}:
        raise NetworkToolError("unsupported_sitemap", "The XML root must be urlset or sitemapindex.")
    item_name = "url" if kind == "urlset" else "sitemap"
    entries = []
    for item in list(root):
        if item.tag.rsplit("}", 1)[-1] != item_name:
            continue
        fields = {}
        for child in list(item):
            name = child.tag.rsplit("}", 1)[-1]
            if name in {"loc", "lastmod"} and child.text:
                fields[name] = child.text.strip()[:2048]
        if fields.get("loc"):
            entries.append(fields)
    return {"type": kind, "count": len(entries), "samples": tuple(entries[:25])}


class MetaParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.values = {}
        self._in_title = False
        self._title_parts = []

    def handle_starttag(self, tag, attrs):
        attributes = {key.lower(): value for key, value in attrs if key and value is not None}
        if tag.lower() == "title" and "title" not in self.values:
            self._in_title = True
        elif tag.lower() == "meta":
            key = (attributes.get("name") or attributes.get("property") or "").lower()
            mapping = {
                "description": "description", "robots": "robots",
                "og:title": "og_title", "og:description": "og_description", "og:url": "og_url",
                "twitter:card": "twitter_card", "twitter:title": "twitter_title",
                "twitter:description": "twitter_description",
            }
            if key in mapping and mapping[key] not in self.values:
                self.values[mapping[key]] = attributes.get("content", "")[:4096]
        elif tag.lower() == "link" and "canonical" in attributes.get("rel", "").lower().split():
            self.values.setdefault("canonical", attributes.get("href", "")[:2048])

    def handle_endtag(self, tag):
        if tag.lower() == "title" and self._in_title:
            self._in_title = False
            self.values.setdefault("title", "".join(self._title_parts).strip()[:4096])

    def handle_data(self, data):
        if self._in_title:
            self._title_parts.append(data)


def parse_meta_tags(text):
    parser = MetaParser()
    parser.feed(text)
    parser.close()
    if parser._title_parts and "title" not in parser.values:
        parser.values["title"] = "".join(parser._title_parts).strip()[:4096]
    return parser.values


@lru_cache(maxsize=1)
def rdap_bootstrap():
    result = safe_http_request(IANA_RDAP_BOOTSTRAP, fetch_body=True, max_body=RDAP_BODY_LIMIT)
    if result.status != 200:
        raise NetworkToolError("rdap_bootstrap", "The IANA RDAP registry list was unavailable.")
    content_type = result.headers.get("content-type", "").lower()
    if content_type and "json" not in content_type:
        raise NetworkToolError("rdap_bootstrap", "The IANA RDAP registry list was not JSON.")
    try:
        document = json.loads(result.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NetworkToolError("rdap_bootstrap", "The IANA RDAP registry list was invalid.") from error
    services = document.get("services")
    if not isinstance(services, list):
        raise NetworkToolError("rdap_bootstrap", "The IANA RDAP registry list was invalid.")
    normalized_services = []
    for service in services:
        if (
            isinstance(service, list) and len(service) == 2
            and isinstance(service[0], list) and isinstance(service[1], list)
        ):
            normalized_services.append((
                tuple(item.lower() for item in service[0] if isinstance(item, str)),
                tuple(item for item in service[1] if isinstance(item, str)),
            ))
    if not normalized_services:
        raise NetworkToolError("rdap_bootstrap", "The IANA RDAP registry list contained no usable services.")
    return tuple(normalized_services)


def rdap_lookup(value):
    domain = normalize_domain(value)
    tld = domain.rsplit(".", 1)[-1]
    service_url = None
    for tlds, urls in rdap_bootstrap():
        if tld in {item.lower() for item in tlds}:
            service_url = next((url for url in urls if url.startswith("https://")), None)
            break
    if not service_url:
        raise NetworkToolError("rdap_unavailable", "No HTTPS RDAP service was listed for this top-level domain.")
    query_url = f"{service_url.rstrip('/')}/domain/{domain}"
    result = safe_http_request(query_url, fetch_body=True, max_body=RDAP_BODY_LIMIT)
    if result.status != 200:
        raise NetworkToolError("rdap_response", f"The registry RDAP service returned HTTP {result.status}.")
    content_type = result.headers.get("content-type", "").lower()
    if content_type and "json" not in content_type:
        raise NetworkToolError("rdap_response", "The registry RDAP response was not JSON.")
    try:
        data = json.loads(result.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NetworkToolError("rdap_response", "The registry returned invalid RDAP JSON.") from error
    if not isinstance(data, dict):
        raise NetworkToolError("rdap_response", "The registry returned invalid RDAP JSON.")
    events = {}
    event_items = data.get("events", ())
    if not isinstance(event_items, list):
        event_items = ()
    for event in event_items:
        if (
            isinstance(event, dict)
            and isinstance(event.get("eventAction"), str)
            and isinstance(event.get("eventDate"), str)
        ):
            events.setdefault(event["eventAction"], event["eventDate"][:40])
    registrar = None
    entity_items = data.get("entities", ())
    if not isinstance(entity_items, list):
        entity_items = ()
    for entity in entity_items:
        if not isinstance(entity, dict) or "registrar" not in entity.get("roles", ()):
            continue
        vcard = entity.get("vcardArray", [None, []])
        if isinstance(vcard, list) and len(vcard) == 2:
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4 and field[0] in {"fn", "org"}:
                    registrar = str(field[3])[:300]
                    break
        if registrar:
            break
    nameserver_items = data.get("nameservers", ())
    if not isinstance(nameserver_items, list):
        nameserver_items = ()
    nameservers = tuple(
        item.get("ldhName", "")[:253].lower()
        for item in nameserver_items
        if isinstance(item, dict) and isinstance(item.get("ldhName"), str)
    )[:100]
    statuses = data.get("status", ())
    if not isinstance(statuses, list):
        statuses = ()
    ldh_name = data.get("ldhName")
    if not isinstance(ldh_name, str):
        ldh_name = domain
    return {
        "domain": ldh_name.lower()[:253],
        "statuses": tuple(str(item)[:100] for item in statuses if isinstance(item, str))[:100],
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "changed": events.get("last changed") or events.get("last update of RDAP database"),
        "registrar": registrar,
        "nameservers": nameservers,
        "source": result.url,
    }


def approximate_age(created):
    if not created:
        return None
    try:
        moment = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    days = max(0, (datetime.now(timezone.utc) - moment).days)
    years, remaining = divmod(days, 365)
    months, residual_days = divmod(remaining, 30)
    return {"years": years, "months": months, "days": residual_days, "total_days": days}
