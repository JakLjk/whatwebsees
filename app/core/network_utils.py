"""Safe, reusable network primitives for user-supplied public targets."""

from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
from ipaddress import ip_address
import socket
import ssl
from time import monotonic
from urllib.parse import urljoin, urlsplit, urlunsplit

import dns.exception
import dns.resolver


CONNECT_TIMEOUT = 4.0
READ_TIMEOUT = 6.0
MAX_REDIRECTS = 4
MAX_RESPONSE_BODY = 16 * 1024
HTTP_TOTAL_TIMEOUT = 18.0
TLS_TOTAL_TIMEOUT = 12.0
ALLOWED_SCHEMES = {"http": 80, "https": 443}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class NetworkToolError(Exception):
    """A deliberately user-safe network diagnostic error."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ResolvedTarget:
    hostname: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class HTTPResult:
    url: str
    status: int
    reason: str
    elapsed_ms: int
    redirects: int
    headers: dict[str, str]


@dataclass(frozen=True)
class TLSResult:
    hostname: str
    subject: str
    issuer: str
    san_hostnames: tuple[str, ...]
    valid_from: datetime | None
    valid_until: datetime | None
    days_remaining: int | None
    tls_version: str
    cipher: str


def normalize_hostname(value):
    """Return a lower-case ASCII hostname without permitting URL syntax."""
    if not isinstance(value, str):
        raise NetworkToolError("invalid_host", "Enter a valid hostname or domain.")

    candidate = value.strip().rstrip(".")
    if not candidate or len(candidate) > 253:
        raise NetworkToolError("invalid_host", "Enter a valid hostname or domain.")
    if any(ord(character) < 33 for character in candidate):
        raise NetworkToolError("invalid_host", "The hostname contains invalid characters.")
    try:
        address = ip_address(candidate)
    except ValueError:
        address = None
    if address is not None:
        return str(address)
    if any(character in candidate for character in "/\\@:#?%[]"):
        raise NetworkToolError("invalid_host", "Enter a hostname only, without a URL, path, port, or credentials.")

    try:
        ascii_hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise NetworkToolError("invalid_host", "The internationalized hostname is not valid.") from error

    labels = ascii_hostname.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        raise NetworkToolError("invalid_host", "Enter a valid public hostname, such as example.com.")

    forbidden_suffixes = (
        ".localhost",
        ".local",
        ".localdomain",
        ".internal",
        ".home",
        ".home.arpa",
        ".lan",
        ".test",
        ".invalid",
        ".example",
        ".onion",
    )
    if (
        ascii_hostname in {"localhost", "home.arpa"}
        or ascii_hostname.endswith(forbidden_suffixes)
    ):
        raise NetworkToolError("non_public_target", "Local and internal hostnames are not allowed.")
    return ascii_hostname


def normalize_domain(value):
    """Normalize a domain name and reject IP-address literals."""
    hostname = normalize_hostname(value)
    try:
        ip_address(hostname)
    except ValueError:
        return hostname
    raise NetworkToolError("invalid_host", "Enter a domain or hostname, not an IP address.")


def is_public_address(value):
    """Return whether an address is safe for an Internet-only connection."""
    try:
        address = value if hasattr(value, "is_global") else ip_address(value)
    except ValueError:
        return False

    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None and not mapped.is_global:
        return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def _remaining_timeout(deadline, maximum):
    if deadline is None:
        return maximum
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise NetworkToolError("timeout", "The network operation timed out.")
    return min(maximum, remaining)


def _resolve_addresses(hostname, deadline=None):
    """Resolve public address record types with bounded resolver timeouts."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    addresses = []
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(
                hostname,
                record_type,
                raise_on_no_answer=False,
                search=False,
                lifetime=_remaining_timeout(deadline, 4.0),
            )
        except dns.resolver.NXDOMAIN:
            break
        except dns.resolver.NoAnswer:
            continue
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as error:
            raise NetworkToolError("timeout", "The hostname lookup timed out.") from error
        except dns.resolver.NoNameservers as error:
            raise NetworkToolError("resolver_unavailable", "No DNS resolver could answer the hostname lookup.") from error
        except dns.exception.DNSException as error:
            raise NetworkToolError("dns_error", "The hostname could not be resolved.") from error
        if answer.rrset is not None:
            addresses.extend(item.address for item in answer)
    return tuple(dict.fromkeys(addresses))


def resolve_public_host(hostname, port, *, deadline=None):
    """Resolve once, reject every non-public answer, and return pinned IPs."""
    normalized = normalize_hostname(hostname)
    try:
        literal = ip_address(normalized)
    except ValueError:
        literal = None

    if literal is not None:
        addresses = (str(literal),)
    else:
        addresses = _resolve_addresses(normalized, deadline)
        if len(addresses) > 32:
            raise NetworkToolError("dns_error", "The hostname returned too many address candidates.")

    if not addresses:
        raise NetworkToolError("dns_error", "The hostname returned no usable IP addresses.")
    if any(not is_public_address(address) for address in addresses):
        raise NetworkToolError(
            "non_public_target",
            "The hostname resolves to a non-public address, so WhatWebSees will not connect to it.",
        )
    return ResolvedTarget(normalized, addresses)


def normalize_http_url(value, *, default_scheme="https"):
    """Normalize a public HTTP(S) URL without performing DNS resolution."""
    if not isinstance(value, str):
        raise NetworkToolError("invalid_url", "Enter a valid HTTP or HTTPS URL.")
    candidate = value.strip()
    if not candidate or len(candidate) > 2048 or any(ord(character) < 32 for character in candidate):
        raise NetworkToolError("invalid_url", "Enter a valid HTTP or HTTPS URL.")
    if "://" not in candidate:
        candidate = f"{default_scheme}://{candidate}"

    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as error:
        raise NetworkToolError("invalid_url", "The URL contains an invalid host or port.") from error

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise NetworkToolError("unsupported_scheme", "Only HTTP and HTTPS URLs are supported.")
    if parsed.username is not None or parsed.password is not None:
        raise NetworkToolError("userinfo", "URLs containing usernames or passwords are not allowed.")
    if not parsed.hostname:
        raise NetworkToolError("invalid_url", "The URL must include a hostname.")
    if port is not None and port != ALLOWED_SCHEMES[scheme]:
        raise NetworkToolError("disallowed_port", "Only the standard HTTP and HTTPS ports are allowed.")

    hostname = normalize_hostname(parsed.hostname)
    try:
        literal = ip_address(hostname)
    except ValueError:
        literal = None
    display_host = f"[{hostname}]" if literal is not None and literal.version == 6 else hostname
    path = parsed.path or "/"
    return urlunsplit((scheme, display_host, path, parsed.query, ""))


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname, address, port, deadline):
        super().__init__(hostname, port=port, timeout=_remaining_timeout(deadline, CONNECT_TIMEOUT))
        self._address = address
        self._deadline = deadline

    def connect(self):
        self.sock = _connect_to_ip(self._address, self.port, self.timeout)
        self.sock.settimeout(_remaining_timeout(self._deadline, READ_TIMEOUT))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, address, port, deadline, context):
        super().__init__(
            hostname,
            port=port,
            timeout=_remaining_timeout(deadline, CONNECT_TIMEOUT),
            context=context,
        )
        self._address = address
        self._deadline = deadline

    def connect(self):
        raw_socket = _connect_to_ip(self._address, self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
            self.sock.settimeout(_remaining_timeout(self._deadline, READ_TIMEOUT))
        except Exception:
            raw_socket.close()
            raise


def _connect_to_ip(address, port, timeout):
    """Connect to a numeric address without invoking hostname resolution."""
    parsed = ip_address(address)
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    destination = (str(parsed), port, 0, 0) if parsed.version == 6 else (str(parsed), port)
    try:
        connection.connect(destination)
    except Exception:
        connection.close()
        raise
    return connection


def _make_connection(parsed, address, deadline):
    port = ALLOWED_SCHEMES[parsed.scheme]
    if parsed.scheme == "https":
        return _PinnedHTTPSConnection(
            parsed.hostname,
            address,
            port,
            deadline,
            ssl.create_default_context(),
        )
    return _PinnedHTTPConnection(parsed.hostname, address, port, deadline)


def _request_once(url, method, deadline):
    parsed = urlsplit(url)
    target = resolve_public_host(
        parsed.hostname,
        ALLOWED_SCHEMES[parsed.scheme],
        deadline=deadline,
    )
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    headers = {
        "Accept": "*/*",
        "Connection": "close",
        "User-Agent": "WhatWebSees/1.0 (+https://whatwebsees.com/)",
    }
    if method == "GET":
        headers["Range"] = f"bytes=0-{MAX_RESPONSE_BODY - 1}"

    last_error = None
    for address in target.addresses:
        connection = _make_connection(parsed, address, deadline)
        try:
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            if method == "GET":
                response.read(MAX_RESPONSE_BODY + 1)
            result_headers = {}
            for name, value in response.getheaders():
                lower_name = name.lower()
                if lower_name not in result_headers:
                    result_headers[lower_name] = value[:4096]
            result = (response.status, response.reason or "", result_headers)
            connection.close()
            return result
        except (OSError, http.client.HTTPException, ssl.SSLError) as error:
            last_error = error
            connection.close()

    if isinstance(last_error, (TimeoutError, socket.timeout)):
        raise NetworkToolError("timeout", "The website did not respond before the timeout.") from last_error
    if isinstance(last_error, ssl.SSLCertVerificationError):
        raise NetworkToolError("tls_validation", "The website's TLS certificate could not be validated.") from last_error
    if isinstance(last_error, ConnectionRefusedError):
        raise NetworkToolError("connection_refused", "The website refused the connection.") from last_error
    raise NetworkToolError("connection_error", "A connection to the website could not be completed.") from last_error


def safe_http_request(value, *, fallback_get=True):
    """Perform a bounded request, validating DNS and every redirect hop."""
    current_url = normalize_http_url(value)
    redirects = 0
    method = "HEAD"
    started = monotonic()
    deadline = started + HTTP_TOTAL_TIMEOUT

    while True:
        status, reason, headers = _request_once(current_url, method, deadline)
        if method == "HEAD" and fallback_get and status in {405, 501}:
            method = "GET"
            status, reason, headers = _request_once(current_url, method, deadline)

        location = headers.get("location")
        if status in REDIRECT_STATUSES and location:
            if redirects >= MAX_REDIRECTS:
                raise NetworkToolError("redirect_limit", "The website exceeded the redirect limit.")
            current_url = normalize_http_url(urljoin(current_url, location))
            redirects += 1
            method = "HEAD"
            continue

        return HTTPResult(
            url=current_url,
            status=status,
            reason=reason,
            elapsed_ms=max(1, round((monotonic() - started) * 1000)),
            redirects=redirects,
            headers=headers,
        )


def _distinguished_name(entries):
    parts = []
    for group in entries:
        for key, value in group:
            parts.append(f"{key}={value}")
    return ", ".join(parts)[:1000]


def check_tls_certificate(value):
    """Validate and summarize the TLS certificate on the fixed HTTPS port."""
    hostname = normalize_domain(value)
    deadline = monotonic() + TLS_TOTAL_TIMEOUT
    target = resolve_public_host(hostname, 443, deadline=deadline)
    context = ssl.create_default_context()
    last_error = None

    for address in target.addresses:
        raw_socket = None
        try:
            raw_socket = _connect_to_ip(
                address,
                443,
                _remaining_timeout(deadline, CONNECT_TIMEOUT),
            )
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                certificate = tls_socket.getpeercert()
                valid_from = _certificate_datetime(certificate.get("notBefore"))
                valid_until = _certificate_datetime(certificate.get("notAfter"))
                remaining = None
                if valid_until is not None:
                    remaining = (valid_until - datetime.now(timezone.utc)).days
                cipher_info = tls_socket.cipher()
                return TLSResult(
                    hostname=hostname,
                    subject=_distinguished_name(certificate.get("subject", ())) or "Unavailable",
                    issuer=_distinguished_name(certificate.get("issuer", ())) or "Unavailable",
                    san_hostnames=tuple(
                        value[:253]
                        for kind, value in certificate.get("subjectAltName", ())[:100]
                        if kind == "DNS"
                    ),
                    valid_from=valid_from,
                    valid_until=valid_until,
                    days_remaining=remaining,
                    tls_version=tls_socket.version() or "Unavailable",
                    cipher=cipher_info[0] if cipher_info else "Unavailable",
                )
        except (OSError, ssl.SSLError) as error:
            last_error = error
            if raw_socket is not None:
                try:
                    raw_socket.close()
                except OSError:
                    pass

    if isinstance(last_error, ssl.SSLCertVerificationError):
        message = "The certificate is expired, untrusted, or does not match the hostname."
        raise NetworkToolError("tls_validation", message) from last_error
    if isinstance(last_error, (TimeoutError, socket.timeout)):
        raise NetworkToolError("timeout", "The TLS service did not respond before the timeout.") from last_error
    if isinstance(last_error, ConnectionRefusedError):
        raise NetworkToolError("connection_refused", "The host refused a TLS connection on port 443.") from last_error
    raise NetworkToolError("tls_error", "A validated TLS connection could not be completed on port 443.") from last_error


def _certificate_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None
