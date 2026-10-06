from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv6Address, ip_address
from typing import Literal, Mapping

DEFAULT_PORTS = {"http": 80, "https": 443}

_SCHEME_RE = re.compile(r"[a-z][a-z0-9+.-]*$")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class OriginPatternError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ParsedOrigin:
    scheme: str
    host: str
    port: int | None
    is_ipv6: bool

    @property
    def default_port(self) -> int | None:
        return DEFAULT_PORTS.get(self.scheme)

    @property
    def effective_port(self) -> int | None:
        return self.port if self.port is not None else self.default_port

    @property
    def canonical(self) -> str:
        host = f"[{self.host}]" if self.is_ipv6 else self.host
        port = f":{self.port}" if self.port is not None else ""
        return f"{self.scheme}://{host}{port}"


@dataclass(frozen=True, slots=True)
class OriginPattern:
    scheme: str
    host: str
    port_range: tuple[int, int]
    wildcard: Literal["none", "subdomain", "descendants"] = "none"
    is_ipv6: bool = False

    def matches(self, origin: ParsedOrigin) -> bool:
        if origin.scheme != self.scheme or not self._port_matches(origin):
            return False

        if self.is_ipv6 or origin.is_ipv6:
            return self.wildcard == "none" and origin.host == self.host

        pattern_labels = self.host.split(".")
        origin_labels = origin.host.split(".")
        suffix_length = len(pattern_labels)

        if self.wildcard == "none":
            return origin_labels == pattern_labels

        if len(origin_labels) <= suffix_length:
            return False

        if origin_labels[-suffix_length:] != pattern_labels:
            return False

        return self.wildcard == "descendants" or len(origin_labels) == suffix_length + 1

    def _port_matches(self, origin: ParsedOrigin) -> bool:
        port = origin.effective_port
        return (
            port is not None
            and self.port_range[0] <= port <= self.port_range[1]
        )


def parse_origin(value: str) -> ParsedOrigin | None:
    if not isinstance(value, str) or not value or value in {"null", "file://"}:
        return None
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        return None

    scheme, separator, authority = value.partition("://")
    scheme = scheme.lower()
    if not separator or not _SCHEME_RE.fullmatch(scheme) or not authority:
        return None
    if any(char in authority for char in "/?#@"):
        return None

    if authority.startswith("["):
        closing_bracket = authority.find("]")
        if closing_bracket == -1 or "[" in authority[1:]:
            return None
        host = authority[1:closing_bracket]
        port_text = authority[closing_bracket + 1 :]
        if port_text and not port_text.startswith(":"):
            return None
        if port_text:
            port = _parse_port(port_text[1:], require_default=False)
        else:
            port = -1
        address = _parse_ipv6(host)
        if address is None or port is None:
            return None
        canonical_port = _canonical_port(scheme, port)
        return ParsedOrigin(scheme, address.compressed, canonical_port, True)

    if authority.count(":") > 1 or authority.startswith(":"):
        return None
    host, separator, port_text = authority.rpartition(":")
    if not separator:
        host = port_text
        port_text = ""

    port = _parse_port(port_text, require_default=not separator)
    if port is None:
        return None

    try:
        address = ip_address(host)
    except ValueError:
        is_ipv6 = False
        try:
            normalized_host = _normalize_domain(host)
        except (OriginPatternError, UnicodeError):
            return None
    else:
        normalized_host = address.compressed
        is_ipv6 = isinstance(address, IPv6Address)

    canonical_port = _canonical_port(scheme, port)
    return ParsedOrigin(scheme, normalized_host, canonical_port, is_ipv6)


def compile_origin_pattern(value: Mapping[str, object]) -> OriginPattern:
    if not isinstance(value, Mapping):
        raise OriginPatternError("pattern must be a mapping")

    allowed_keys = {"scheme", "host", "port_range"}
    extra_keys = set(value) - allowed_keys
    missing_keys = allowed_keys - set(value)
    if extra_keys:
        raise OriginPatternError(f"unexpected keys: {sorted(extra_keys)}")
    if missing_keys:
        raise OriginPatternError(f"missing keys: {sorted(missing_keys)}")

    scheme = _compile_scheme(value["scheme"])
    host, wildcard, is_ipv6 = _compile_host(value["host"])
    port_range = _compile_port_range(value["port_range"])
    return OriginPattern(scheme, host, port_range, wildcard, is_ipv6)


def _parse_port(value: str, require_default: bool) -> int | None:
    if value == "":
        return -1 if require_default else None
    if not value.isascii() or not value.isdigit():
        return None
    if len(value) > 1 and value.startswith("0"):
        return None
    port = int(value)
    if not 1 <= port <= 65535:
        return None
    return port


def _canonical_port(scheme: str, port: int) -> int | None:
    if port == -1:
        return None
    return None if DEFAULT_PORTS.get(scheme) == port else port


def _parse_ipv6(value: str) -> IPv6Address | None:
    try:
        address = ip_address(value)
    except ValueError:
        return None
    return address if isinstance(address, IPv6Address) else None


def _compile_scheme(value: object) -> str:
    if not isinstance(value, str):
        raise OriginPatternError("scheme must be a string")
    scheme = value.lower()
    if not _SCHEME_RE.fullmatch(scheme):
        raise OriginPatternError(f"invalid scheme: {value!r}")
    return scheme


def _compile_host(
    value: object,
) -> tuple[str, Literal["none", "subdomain", "descendants"], bool]:
    if not isinstance(value, str) or not value:
        raise OriginPatternError("host must be a non-empty string")

    wildcard: Literal["none", "subdomain", "descendants"] = "none"
    host = value
    if host.startswith("**."):
        wildcard = "descendants"
        host = host[3:]
    elif host.startswith("*."):
        wildcard = "subdomain"
        host = host[2:]

    if host.startswith("[") or host.endswith("]"):
        raise OriginPatternError("IPv6 hosts must be supplied without brackets")
    if "*" in host:
        raise OriginPatternError("wildcards are only supported as a leading label")

    try:
        address = ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if wildcard != "none":
            raise OriginPatternError("IP address hosts cannot use wildcards")
        return address.compressed, "none", isinstance(address, IPv6Address)

    try:
        return _normalize_domain(host), wildcard, False
    except (OriginPatternError, UnicodeError) as exc:
        raise OriginPatternError(f"invalid host: {value!r}") from exc


def _compile_port_range(value: object) -> tuple[int, int]:
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise OriginPatternError("port_range must be a list or tuple of two integers")
    if not all(
        isinstance(port, int) and not isinstance(port, bool) for port in value
    ):
        raise OriginPatternError("port_range must contain integers")
    start, end = value
    if (
        not 1 <= start <= 65535
        or not 1 <= end <= 65535
        or start > end
    ):
        raise OriginPatternError(
            "port_range must contain valid ports in ascending order"
        )
    return start, end


def _normalize_domain(value: str) -> str:
    if not value or value.startswith(".") or value.endswith(".") or ".." in value:
        raise OriginPatternError("invalid domain name")
    try:
        encoded = value.lower().encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise OriginPatternError("invalid domain name") from exc

    labels = encoded.split(".")
    wildcard_length = (
        4 if value.startswith("**.") else 2 if value.startswith("*.") else 0
    )
    if len(encoded) + wildcard_length > 253:
        raise OriginPatternError("domain name is too long")
    for label in labels:
        if not 1 <= len(label) <= 63 or not _DNS_LABEL_RE.fullmatch(label):
            raise OriginPatternError("invalid domain label")
        if label.startswith("xn--"):
            try:
                label.encode("ascii").decode("idna")
            except UnicodeError as exc:
                raise OriginPatternError("invalid IDNA label") from exc
    return encoded
