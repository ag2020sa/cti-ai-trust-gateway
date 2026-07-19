"""URL, DNS, SSRF, redirect, and response-boundary enforcement."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from cti_trust_gateway.delivery.config import OpenCTIConfig

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
_METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
}


class OpenCTISecurityError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class DestinationTarget:
    scheme: str
    host: str
    port: int
    origin: str
    graphql_path: str
    addresses: tuple[str, ...] = ()


def _normalized_host(host: str) -> str:
    try:
        candidate = host.rstrip(".")
        try:
            return ipaddress.ip_address(candidate).compressed.lower()
        except ValueError:
            if re.fullmatch(r"[0-9.]+", candidate):
                raise OpenCTISecurityError("OPENCTI_URL_INVALID") from None
            return candidate.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as exc:
        raise OpenCTISecurityError("OPENCTI_URL_INVALID") from exc


def _authority(host: str, port: int) -> str:
    rendered = f"[{host}]" if ":" in host else host
    return f"{rendered}:{port}"


def _allowlist_authority(value: str) -> str:
    try:
        if value.startswith("["):
            parsed = urlsplit(f"https://{value}")
            if parsed.hostname is None:
                raise ValueError
            return _authority(_normalized_host(parsed.hostname), parsed.port or 443)
        if value.count(":") == 1:
            host_value, port_value = value.rsplit(":", 1)
            if port_value.isdigit():
                port = int(port_value)
                if not 1 <= port <= 65535:
                    raise ValueError
                return _authority(_normalized_host(host_value), port)
        return _authority(_normalized_host(value), 443)
    except (ValueError, OpenCTISecurityError) as exc:
        raise OpenCTISecurityError("OPENCTI_HOST_ALLOWLIST_INVALID") from exc


def parse_destination(config: OpenCTIConfig) -> DestinationTarget:
    config.validate_nonsecret()
    try:
        parsed = urlsplit(config.url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise OpenCTISecurityError("OPENCTI_URL_INVALID") from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        code = "OPENCTI_HTTPS_REQUIRED" if parsed.scheme == "http" else "OPENCTI_URL_INVALID"
        raise OpenCTISecurityError(code)
    host = _normalized_host(hostname)
    allowlist = {_allowlist_authority(item) for item in config.host_allowlist}
    if _authority(host, port) not in allowlist:
        raise OpenCTISecurityError("OPENCTI_HOST_NOT_ALLOWLISTED")
    if not 1 <= port <= 65535:
        raise OpenCTISecurityError("OPENCTI_URL_INVALID")
    default_port = 443
    rendered_host = f"[{host}]" if ":" in host else host
    authority = rendered_host if port == default_port else f"{rendered_host}:{port}"
    return DestinationTarget(
        scheme=parsed.scheme,
        host=host,
        port=port,
        origin=f"{parsed.scheme}://{authority}",
        graphql_path="/graphql",
    )


def _address_allowed(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, config: OpenCTIConfig
) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _address_allowed(address.ipv4_mapped, config)
    if (
        address in _METADATA_ADDRESSES
        or address.is_multicast
        or address.is_unspecified
        or address.is_link_local
        or address.is_reserved
    ):
        return False
    if address.is_loopback:
        return config.allow_loopback
    if any(address in network for network in _PRIVATE_NETWORKS):
        return config.allow_private
    return address.is_global


def resolve_destination(config: OpenCTIConfig) -> DestinationTarget:
    target = parse_destination(config)
    try:
        answers = socket.getaddrinfo(
            target.host,
            target.port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise OpenCTISecurityError("OPENCTI_DNS_FAILED") from exc
    addresses = tuple(sorted({str(item[4][0]) for item in answers}))
    if not addresses:
        raise OpenCTISecurityError("OPENCTI_DNS_FAILED")
    parsed_addresses = [ipaddress.ip_address(value) for value in addresses]
    if not all(_address_allowed(address, config) for address in parsed_addresses):
        raise OpenCTISecurityError("OPENCTI_SSRF_BLOCKED")
    return DestinationTarget(
        scheme=target.scheme,
        host=target.host,
        port=target.port,
        origin=target.origin,
        graphql_path=target.graphql_path,
        addresses=addresses,
    )


def sanitize_message(value: object, *, limit: int = 500) -> str:
    text = str(value)
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+\-/]+=*", "Bearer [REDACTED]", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text[:limit]
