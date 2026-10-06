from __future__ import annotations

import pytest

from corsheaders.origin_patterns import (
    OriginPatternError,
    compile_origin_pattern,
    parse_origin,
)


@pytest.mark.parametrize(
    ("host", "origin"),
    [
        ("example.com", "https://example.com"),
        ("example.com", "https://example.com:443"),
        ("*.example.com", "https://a.example.com"),
        ("**.example.com", "https://a.example.com"),
        ("**.example.com", "https://a.b.example.com"),
        ("例え.jp", "https://xn--r8jz45g.jp"),
        ("::1", "https://[0:0:0:0:0:0:0:1]:443"),
    ],
)
def test_pattern_matches(host: str, origin: str) -> None:
    pattern = compile_origin_pattern(
        {"scheme": "https", "host": host, "port_range": (443, 443)}
    )
    parsed_origin = parse_origin(origin)
    assert parsed_origin is not None
    assert pattern.matches(parsed_origin)


@pytest.mark.parametrize(
    ("host", "origin"),
    [
        ("example.com", "https://a.example.com"),
        ("*.example.com", "https://example.com"),
        ("*.example.com", "https://a.b.example.com"),
        ("*.example.com", "https://badexample.com"),
        ("**.example.com", "https://example.com"),
        ("**.example.com", "https://badexample.com"),
    ],
)
def test_pattern_does_not_match(host: str, origin: str) -> None:
    pattern = compile_origin_pattern(
        {"scheme": "https", "host": host, "port_range": (443, 443)}
    )
    parsed_origin = parse_origin(origin)
    assert parsed_origin is not None
    assert not pattern.matches(parsed_origin)


@pytest.mark.parametrize(
    "origin",
    [
        "null",
        "file://",
        "https://user@example.com",
        "https://example.com/path",
        "https://example.com#fragment",
        "https://example.com,https://other.example.com",
        "https://example.com:65536",
        "https://example.com:01",
        "https://example.com:",
        "https://[::1",
    ],
)
def test_parse_origin_rejects_unsafe_or_malformed_values(origin: str) -> None:
    assert parse_origin(origin) is None


def test_canonical_origin() -> None:
    parsed_origin = parse_origin("https://[0:0:0:0:0:0:0:1]:443")
    assert parsed_origin is not None
    assert parsed_origin.canonical == "https://[::1]"


@pytest.mark.parametrize(
    "pattern",
    [
        "not-a-mapping",
        {"scheme": "https", "host": "example.com"},
        {"scheme": "https", "host": "example.com", "ports": (443, 443)},
        {"scheme": "https", "host": "*.example.com", "port_range": (443,)},
        {"scheme": "https", "host": "*.example.com", "port_range": (444, 443)},
        {"scheme": "https", "host": "*", "port_range": (443, 443)},
        {"scheme": "https", "host": "a.*.com", "port_range": (443, 443)},
        {"scheme": "https", "host": "*.127.0.0.1", "port_range": (443, 443)},
        {"scheme": "https", "host": "[::1]", "port_range": (443, 443)},
        {"scheme": "https", "host": "bad_domain", "port_range": (443, 443)},
        {"scheme": "bad scheme", "host": "example.com", "port_range": (443, 443)},
    ],
)
def test_compile_origin_pattern_rejects_invalid_values(pattern: object) -> None:
    with pytest.raises(OriginPatternError):
        compile_origin_pattern(pattern)  # type: ignore[arg-type]
