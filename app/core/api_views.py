"""Versioned, machine-readable diagnostic API views."""

import json
from ipaddress import ip_address

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .diagnostic_utils import calculate_subnet, convert_punycode
from .dns_utils import lookup_records
from .network_utils import (
    NetworkToolError,
    check_tls_certificate,
    is_public_address,
    normalize_http_url,
    safe_http_request,
)
from .views import SECURITY_HEADERS, SERVER_HEADER_ALLOWLIST, dbip_location


API_MAX_BODY_BYTES = 4096
API_DNS_TYPES = frozenset(("A", "AAAA", "CNAME", "MX", "TXT", "NS"))


def _json_response(payload, *, status=200, allow=None):
    response = JsonResponse(payload, status=status)
    response["Cache-Control"] = "no-store"
    response["X-Robots-Tag"] = "noindex, nofollow"
    response["X-Content-Type-Options"] = "nosniff"
    if allow:
        response["Allow"] = allow
    return response


def api_success(data, *, status=200):
    return _json_response({"ok": True, "data": data}, status=status)


def api_error(code, message, *, status=400, allow=None):
    return _json_response(
        {"ok": False, "error": {"code": code, "message": message}},
        status=status,
        allow=allow,
    )


def _error_status(error):
    if error.code in {"nxdomain", "no_answer"}:
        return 404
    if error.code == "timeout":
        return 504
    if error.code in {
        "connection_error",
        "connection_refused",
        "dns_error",
        "resolver_unavailable",
        "tls_error",
        "tls_validation",
    }:
        return 502
    return 400


def _parse_json_object(request, allowed_fields):
    if request.GET:
        raise NetworkToolError(
            "unexpected_query", "Query-string parameters are not accepted by this endpoint."
        )
    if request.content_type != "application/json":
        raise NetworkToolError(
            "unsupported_media_type", "Use Content-Type: application/json."
        )

    content_length = request.META.get("CONTENT_LENGTH", "")
    if content_length:
        try:
            if int(content_length) > API_MAX_BODY_BYTES:
                raise NetworkToolError(
                    "request_too_large",
                    f"The JSON request body must not exceed {API_MAX_BODY_BYTES} bytes.",
                )
        except ValueError as error:
            raise NetworkToolError(
                "invalid_content_length", "The Content-Length header is invalid."
            ) from error

    body = request.read(API_MAX_BODY_BYTES + 1)
    if len(body) > API_MAX_BODY_BYTES:
        raise NetworkToolError(
            "request_too_large",
            f"The JSON request body must not exceed {API_MAX_BODY_BYTES} bytes.",
        )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NetworkToolError(
            "invalid_json", "The request body must contain valid UTF-8 JSON."
        ) from error
    if not isinstance(payload, dict):
        raise NetworkToolError("invalid_json_object", "The JSON body must be an object.")

    unknown = sorted(set(payload) - set(allowed_fields))
    if unknown:
        raise NetworkToolError(
            "unknown_field", f"Unknown JSON field: {unknown[0]}."
        )
    missing = sorted(set(allowed_fields) - set(payload))
    if missing:
        raise NetworkToolError(
            "missing_field", f"Required JSON field is missing: {missing[0]}."
        )
    return payload


def _string_value(payload, field, *, maximum):
    value = payload[field]
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise NetworkToolError(
            f"invalid_{field}", f"The {field} field must be a non-empty string."
        )
    return value.strip()


def _post(request, fields, handler):
    if request.method != "POST":
        return api_error(
            "method_not_allowed",
            "This endpoint accepts POST requests only.",
            status=405,
            allow="POST",
        )
    try:
        payload = _parse_json_object(request, fields)
        return api_success(handler(payload))
    except NetworkToolError as error:
        status = _error_status(error)
        if error.code == "unsupported_media_type":
            status = 415
        elif error.code == "request_too_large":
            status = 413
        return api_error(error.code, error.message, status=status)
    except Exception:
        return api_error(
            "internal_error",
            "The diagnostic could not be completed.",
            status=500,
        )


@csrf_exempt
def api_health(request):
    if request.method != "GET":
        return api_error(
            "method_not_allowed",
            "This endpoint accepts GET requests only.",
            status=405,
            allow="GET",
        )
    if request.GET:
        return api_error(
            "unexpected_query", "Query-string parameters are not accepted by this endpoint."
        )
    return api_success({"status": "ok", "api_version": "v1"})


def _http_check(payload):
    initial_url = normalize_http_url(_string_value(payload, "url", maximum=2048))
    result = safe_http_request(initial_url)
    headers = {
        display_name: result.headers[lower_name]
        for lower_name, display_name in SERVER_HEADER_ALLOWLIST
        if lower_name in result.headers
    }
    return {
        "url": initial_url,
        "status_code": result.status,
        "http_response_time_ms": result.elapsed_ms,
        "final_url": result.url,
        "redirect_count": result.redirects,
        "headers": headers,
    }


@csrf_exempt
def api_http_check(request):
    return _post(request, {"url"}, _http_check)


def _dns(payload):
    domain = _string_value(payload, "domain", maximum=253)
    record_type = _string_value(payload, "type", maximum=5).upper()
    if record_type not in API_DNS_TYPES:
        raise NetworkToolError(
            "invalid_record_type",
            "Supported DNS record types are A, AAAA, CNAME, MX, TXT and NS.",
        )
    hostname, groups = lookup_records(domain, record_type)
    group = groups[0]
    records = []
    for value in group["values"]:
        if record_type in {"A", "AAAA"}:
            records.append({"address": value})
        elif record_type == "MX":
            priority, _, exchange = value.partition(" ")
            records.append(
                {"priority": int(priority), "exchange": exchange.rstrip(".")}
            )
        elif record_type == "CNAME":
            records.append({"target": value.rstrip(".")})
        elif record_type == "NS":
            records.append({"nameserver": value.rstrip(".")})
        else:
            records.append({"value": value})
    return {
        "domain": hostname,
        "type": record_type,
        "ttl": group["ttl"],
        "records": records,
    }


@csrf_exempt
def api_dns(request):
    return _post(request, {"domain", "type"}, _dns)


def _redirects(payload):
    initial_url = normalize_http_url(_string_value(payload, "url", maximum=2048))
    result = safe_http_request(initial_url)
    return {
        "initial_url": initial_url,
        "final_url": result.url,
        "redirect_count": result.redirects,
        "hops": [
            {
                "url": hop.url,
                "status_code": hop.status,
                "location": hop.location,
                "http_response_time_ms": hop.elapsed_ms,
            }
            for hop in result.chain
        ],
    }


@csrf_exempt
def api_redirects(request):
    return _post(request, {"url"}, _redirects)


def _isoformat(value):
    return value.isoformat() if value is not None else None


def _tls(payload):
    hostname = _string_value(payload, "hostname", maximum=253)
    result = check_tls_certificate(hostname)
    return {
        "hostname": result.hostname,
        "certificate_valid": True,
        "hostname_match": True,
        "valid_from": _isoformat(result.valid_from),
        "valid_until": _isoformat(result.valid_until),
        "days_remaining": result.days_remaining,
        "issuer": result.issuer,
    }


@csrf_exempt
def api_tls(request):
    return _post(request, {"hostname"}, _tls)


def _security_headers(payload):
    initial_url = normalize_http_url(_string_value(payload, "url", maximum=2048))
    result = safe_http_request(initial_url)
    return {
        "url": initial_url,
        "final_url": result.url,
        "status_code": result.status,
        "headers": {
            label: {
                "present": key in result.headers,
                "value": result.headers.get(key),
            }
            for key, label in SECURITY_HEADERS
        },
        "note": "A missing header is an observation, not confirmation of a vulnerability.",
    }


@csrf_exempt
def api_security_headers(request):
    return _post(request, {"url"}, _security_headers)


def _ip(payload):
    value = _string_value(payload, "ip", maximum=45)
    try:
        address = ip_address(value)
    except ValueError as error:
        raise NetworkToolError("invalid_ip", "Enter a valid IPv4 or IPv6 address.") from error
    if not is_public_address(address):
        raise NetworkToolError(
            "non_public_target",
            "IP lookup is limited to globally routable public addresses.",
        )
    location = dbip_location(address)
    allowed_location = {
        field: location[field]
        for field in (
            "city",
            "region",
            "country_code",
            "country",
            "continent_code",
            "latitude",
            "longitude",
        )
        if field in location
    }
    return {
        "ip": str(address),
        "ip_version": address.version,
        **allowed_location,
        "data_source": "DB-IP City Lite",
    }


@csrf_exempt
def api_ip(request):
    return _post(request, {"ip"}, _ip)


def _subnet(payload):
    return calculate_subnet(_string_value(payload, "cidr", maximum=200))


@csrf_exempt
def api_subnet(request):
    return _post(request, {"cidr"}, _subnet)


def _punycode(payload):
    return convert_punycode(_string_value(payload, "value", maximum=253))


@csrf_exempt
def api_punycode(request):
    return _post(request, {"value"}, _punycode)


@csrf_exempt
def api_not_found(request, unmatched_path):
    return api_error(
        "not_found", "No API v1 endpoint exists at this path.", status=404
    )
