from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

DEFAULT_PORTS = {
    "ftp": 21,
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}

SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*$")

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

MAX_PORT = 65535


class PatternError(ValueError):
    """
    Raised when a structured origin pattern is invalid.
    """


@dataclass(frozen=True)
class OriginPattern:
    """
    A parsed, normalized structured origin pattern.
    """

    scheme: str  # lowercase scheme, or "*" for any
    host_labels: tuple[str, ...]  # normalized labels, may contain "*" / "**"
    port_ranges: tuple[tuple[int, int], ...] | None  # None = scheme default port


def normalize_host(host: str) -> str | None:
    """
    Normalize a hostname with fixed rules: strip one trailing dot, lowercase,
    IDNA-encode Unicode names, and compress IPv6 literals. Return None when
    the host is invalid.
    """
    if not host:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if ":" in host:
        try:
            return str(ipaddress.IPv6Address(host))
        except ValueError:
            return None
    host = host.rstrip(".").lower()
    if not host:
        return None
    try:
        normalized = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not all(LABEL_RE.match(label) for label in normalized.split(".")):
        return None
    return normalized


def parse_origin(origin: str) -> tuple[str, str, int | None] | None:
    """
    Strictly parse an Origin header into (scheme, normalized host, port),
    where the port falls back to the scheme default. Return None for anything
    that is not a single, well-formed origin: no userinfo, path, query,
    fragment, whitespace-separated list, or invalid port is repaired here.
    """
    if not origin or any(char.isspace() for char in origin):
        return None
    try:
        url = urlsplit(origin)
    except ValueError:
        return None
    if not url.scheme or not url.hostname:
        return None
    if url.username is not None or url.password is not None:
        return None
    if url.path or url.query or url.fragment:
        return None
    if url.netloc.endswith(":"):
        # Empty port, e.g. "https://example.com:"
        return None
    try:
        port = url.port
    except ValueError:
        return None
    host = normalize_host(url.hostname)
    if host is None:
        return None
    scheme = url.scheme.lower()
    if port is None:
        port = DEFAULT_PORTS.get(scheme)
    return scheme, host, port


def parse_pattern(raw: Any) -> OriginPattern:
    """
    Parse and normalize one structured origin pattern dict, raising
    PatternError with a precise message when invalid.
    """
    if not isinstance(raw, Mapping):
        raise PatternError("pattern should be a dict")
    unknown_keys = set(raw) - {"scheme", "host", "ports"}
    if unknown_keys:
        raise PatternError(f"unknown keys: {', '.join(sorted(unknown_keys))}")

    scheme = raw.get("scheme")
    if not isinstance(scheme, str) or not scheme:
        raise PatternError("'scheme' should be a non-empty string")
    scheme = scheme.lower()
    if scheme != "*" and not SCHEME_RE.match(scheme):
        raise PatternError(f"invalid scheme {scheme!r}")

    host = raw.get("host")
    if not isinstance(host, str) or not host:
        raise PatternError("'host' should be a non-empty string")
    host_labels = _parse_host_pattern(host)

    port_ranges = _parse_ports(raw.get("ports"))

    return OriginPattern(
        scheme=scheme,
        host_labels=host_labels,
        port_ranges=port_ranges,
    )


def _parse_host_pattern(host: str) -> tuple[str, ...]:
    if host.startswith("[") or ":" in host:
        # IPv6 literal: no wildcards allowed
        bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        try:
            return (str(ipaddress.IPv6Address(bare)),)
        except ValueError:
            raise PatternError(f"invalid IPv6 literal {host!r}") from None

    labels = host.rstrip(".").lower().split(".")
    if any(label == "" for label in labels):
        raise PatternError(f"host {host!r} contains an empty label")

    parsed = []
    for index, label in enumerate(labels):
        if label == "**":
            if index != 0:
                raise PatternError("'**' may only appear as the leftmost label")
            parsed.append(label)
        elif label == "*":
            parsed.append(label)
        elif "*" in label:
            raise PatternError(f"wildcards must be whole labels in host {host!r}")
        else:
            try:
                normalized = label.encode("idna").decode("ascii")
            except UnicodeError:
                raise PatternError(
                    f"invalid IDNA label {label!r} in host {host!r}"
                ) from None
            if not LABEL_RE.match(normalized):
                raise PatternError(
                    f"invalid label {label!r} in host {host!r}"
                )
            parsed.append(normalized)
    return tuple(parsed)


def _parse_ports(value: Any) -> tuple[tuple[int, int], ...] | None:
    if value is None:
        return None
    if _is_port_int(value):
        entries = [value]
    elif (
        isinstance(value, tuple)
        and len(value) == 2
        and all(_is_port_int(part) for part in value)
    ):
        # A bare (min, max) tuple is a single range
        entries = [value]
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        entries = list(value)
    else:
        raise PatternError(
            "'ports' should be a port number, a (min, max) range, "
            + "or a list of those"
        )
    if not entries:
        raise PatternError("'ports' should not be an empty list")

    ranges = []
    for entry in entries:
        if _is_port_int(entry):
            low = high = entry
        elif (
            isinstance(entry, Sequence)
            and not isinstance(entry, (str, bytes))
            and len(entry) == 2
            and all(_is_port_int(part) for part in entry)
        ):
            low, high = entry
        else:
            raise PatternError(
                f"port entry {entry!r} should be a number or (min, max) range"
            )
        if not 1 <= low <= high <= MAX_PORT:
            raise PatternError(f"invalid port range {entry!r}")
        ranges.append((low, high))
    return tuple(sorted(ranges))


def _is_port_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def origin_matches_patterns(origin: str, patterns: Sequence[Any]) -> bool:
    """
    Check an Origin header against structured patterns. The origin must parse
    strictly on its own; invalid patterns are skipped (the system checks
    report them at startup).
    """
    if not patterns:
        return False
    parsed = parse_origin(origin)
    if parsed is None:
        return False
    scheme, host, port = parsed
    host_labels = tuple(host.split("."))
    for raw in patterns:
        try:
            pattern = parse_pattern(raw)
        except PatternError:
            continue
        if _pattern_matches(pattern, scheme, host_labels, port):
            return True
    return False


def _pattern_matches(
    pattern: OriginPattern,
    scheme: str,
    host_labels: tuple[str, ...],
    port: int | None,
) -> bool:
    if pattern.scheme != "*" and pattern.scheme != scheme:
        return False
    if not _labels_match(pattern.host_labels, host_labels):
        return False
    if pattern.port_ranges is None:
        return port == DEFAULT_PORTS.get(scheme)
    return port is not None and any(
        low <= port <= high for low, high in pattern.port_ranges
    )


def _labels_match(
    pattern_labels: tuple[str, ...], host_labels: tuple[str, ...]
) -> bool:
    if not pattern_labels:
        return not host_labels
    head, rest = pattern_labels[0], pattern_labels[1:]
    if head == "**":
        # One or more labels
        return any(
            _labels_match(rest, host_labels[index:])
            for index in range(1, len(host_labels) + 1)
        )
    if not host_labels:
        return False
    if head != "*" and head != host_labels[0]:
        return False
    return _labels_match(rest, host_labels[1:])
