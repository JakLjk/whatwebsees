"""Pure, bounded calculations shared by HTML tools and the public API."""

from ipaddress import ip_interface, ip_network

from .network_utils import NetworkToolError


def calculate_subnet(value):
    """Calculate CIDR boundaries without enumerating addresses."""
    if not isinstance(value, str) or len(value) > 200:
        raise NetworkToolError(
            "invalid_cidr",
            "Enter an IPv4 or IPv6 address with a CIDR prefix, such as 192.168.1.50/24.",
        )
    try:
        interface = ip_interface(value.strip())
        network = ip_network(value.strip(), strict=False)
    except ValueError as error:
        raise NetworkToolError(
            "invalid_cidr",
            "Enter an IPv4 or IPv6 address with a CIDR prefix, such as 192.168.1.50/24.",
        ) from error

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
            result.update(
                {
                    "usable": 1,
                    "first_usable": str(network.network_address),
                    "last_usable": str(network.network_address),
                    "host_note": "A /32 represents one host address.",
                }
            )
        elif network.prefixlen == 31:
            result.update(
                {
                    "usable": 2,
                    "first_usable": str(network.network_address),
                    "last_usable": str(network.broadcast_address),
                    "host_note": "Both addresses can be used on an RFC 3021 point-to-point link.",
                }
            )
        else:
            result.update(
                {
                    "usable": network.num_addresses - 2,
                    "first_usable": str(network.network_address + 1),
                    "last_usable": str(network.broadcast_address - 1),
                    "host_note": "Traditional IPv4 host count excludes the network and broadcast addresses.",
                }
            )
    else:
        result["host_note"] = (
            "IPv6 has no broadcast address; address assignment depends on subnet policy."
        )
    return result


def convert_punycode(value):
    """Return normalized Unicode and ASCII forms using Python's IDNA codec."""
    if not isinstance(value, str) or len(value) > 253:
        raise NetworkToolError(
            "invalid_punycode",
            "The domain could not be converted with the platform IDNA implementation.",
        )
    candidate = value.strip().rstrip(".")
    if (
        not candidate
        or any(ord(character) < 33 for character in candidate)
        or any(character in candidate for character in "/\\@:#?%[]")
    ):
        raise NetworkToolError(
            "invalid_punycode",
            "The domain could not be converted with the platform IDNA implementation.",
        )
    try:
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
    except UnicodeError as error:
        raise NetworkToolError(
            "invalid_punycode",
            "The domain could not be converted with the platform IDNA implementation.",
        ) from error
    return {"ascii": ascii_domain, "unicode": unicode_domain}
