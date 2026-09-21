"""Bounded DNS lookups with user-safe error reporting."""

from ipaddress import ip_address
from time import monotonic

import dns.exception
import dns.reversename
import dns.resolver

from .network_utils import NetworkToolError, is_public_address, normalize_domain


DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


def _resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    return resolver


def lookup_records(domain, record_type):
    hostname = normalize_domain(domain)
    requested = record_type.upper()
    if requested != "ALL" and requested not in DNS_RECORD_TYPES:
        raise NetworkToolError("invalid_record_type", "Choose a supported DNS record type.")

    resolver = _resolver()
    types = DNS_RECORD_TYPES if requested == "ALL" else (requested,)
    deadline = monotonic() + (8.0 if requested == "ALL" else 4.0)
    records = []
    try:
        for current_type in types:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise NetworkToolError("timeout", "The DNS query timed out. Try again shortly.")
            try:
                answer = resolver.resolve(
                    hostname,
                    current_type,
                    raise_on_no_answer=False,
                    search=False,
                    lifetime=min(4.0, remaining),
                )
            except dns.resolver.NoAnswer:
                continue
            if answer.rrset is None:
                continue
            records.append(
                {
                    "type": current_type,
                    "ttl": answer.rrset.ttl,
                    "values": tuple(item.to_text()[:4096] for item in answer)[:100],
                }
            )
    except dns.resolver.NXDOMAIN as error:
        raise NetworkToolError("nxdomain", "That domain does not exist in DNS (NXDOMAIN).") from error
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as error:
        raise NetworkToolError("timeout", "The DNS query timed out. Try again shortly.") from error
    except dns.resolver.NoNameservers as error:
        raise NetworkToolError("resolver_unavailable", "No DNS resolver could answer the query.") from error
    except dns.exception.DNSException as error:
        raise NetworkToolError("dns_error", "The DNS query could not be completed.") from error

    if not records:
        raise NetworkToolError("no_answer", "No matching DNS records were found.")
    return hostname, records


def reverse_lookup(value):
    try:
        address = ip_address(value.strip())
    except (AttributeError, ValueError) as error:
        raise NetworkToolError("invalid_ip", "Enter a valid IPv4 or IPv6 address.") from error
    if not is_public_address(address):
        raise NetworkToolError(
            "non_public_target",
            "Reverse DNS lookup is limited to globally routable public addresses.",
        )

    resolver = _resolver()
    try:
        answer = resolver.resolve(
            dns.reversename.from_address(str(address)),
            "PTR",
            raise_on_no_answer=False,
            search=False,
        )
    except dns.resolver.NXDOMAIN as error:
        raise NetworkToolError("no_answer", "No PTR record was found for this address.") from error
    except dns.resolver.NoAnswer as error:
        raise NetworkToolError("no_answer", "No PTR record was found for this address.") from error
    except dns.resolver.NoNameservers as error:
        raise NetworkToolError("resolver_unavailable", "No DNS resolver could answer the reverse query.") from error
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as error:
        raise NetworkToolError("timeout", "The reverse DNS query timed out. Try again shortly.") from error
    except dns.exception.DNSException as error:
        raise NetworkToolError("dns_error", "The reverse DNS query could not be completed.") from error

    if answer.rrset is None:
        raise NetworkToolError("no_answer", "No PTR record was found for this address.")
    hostnames = tuple(dict.fromkeys(item.to_text().rstrip(".")[:253] for item in answer))[:100]
    if not hostnames:
        raise NetworkToolError("no_answer", "No PTR record was found for this address.")
    return str(address), hostnames
