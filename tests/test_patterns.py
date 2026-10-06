from __future__ import annotations

import pytest

from corsheaders.patterns import (
    PatternError,
    normalize_host,
    origin_matches_patterns,
    parse_origin,
    parse_pattern,
)

MATRIX_ORIGINS = (
    "https://example.com",
    "https://a.example.com",
    "https://a.b.example.com",
    "https://badexample.com",
)


class TestHostScopeMatrix:
    @pytest.mark.parametrize(
        ("pattern_host", "expected"),
        [
            ("example.com", [True, False, False, False]),
            ("*.example.com", [False, True, False, False]),
            ("**.example.com", [False, True, True, False]),
            ("*", [False, False, False, False]),
            ("**", [True, True, True, True]),
        ],
    )
    def test_matrix(self, pattern_host, expected):
        patterns = [{"scheme": "https", "host": pattern_host}]
        results = [
            origin_matches_patterns(origin, patterns) for origin in MATRIX_ORIGINS
        ]
        assert results == expected

    def test_single_wildcard_does_not_match_bare_domain(self):
        patterns = [{"scheme": "https", "host": "*.example.com"}]
        assert not origin_matches_patterns("https://example.com", patterns)

    def test_multi_wildcard_requires_at_least_one_label(self):
        patterns = [{"scheme": "https", "host": "**.example.com"}]
        assert not origin_matches_patterns("https://example.com", patterns)

    def test_multi_wildcard_only_leftmost(self):
        with pytest.raises(PatternError):
            parse_pattern({"scheme": "https", "host": "a.**.example.com"})

    def test_wildcard_must_be_whole_label(self):
        with pytest.raises(PatternError):
            parse_pattern({"scheme": "https", "host": "a*.example.com"})


class TestSchemeAndPorts:
    def test_scheme_must_match(self):
        patterns = [{"scheme": "https", "host": "example.com"}]
        assert not origin_matches_patterns("http://example.com", patterns)

    def test_scheme_wildcard(self):
        patterns = [{"scheme": "*", "host": "example.com"}]
        assert origin_matches_patterns("http://example.com", patterns)
        assert origin_matches_patterns("https://example.com", patterns)

    def test_default_port_implied(self):
        patterns = [{"scheme": "https", "host": "example.com"}]
        assert origin_matches_patterns("https://example.com:443", patterns)
        assert not origin_matches_patterns("https://example.com:8443", patterns)

    def test_explicit_port(self):
        patterns = [{"scheme": "http", "host": "example.com", "ports": 8080}]
        assert origin_matches_patterns("http://example.com:8080", patterns)
        assert not origin_matches_patterns("http://example.com", patterns)
        assert not origin_matches_patterns("http://example.com:8081", patterns)

    def test_port_range(self):
        patterns = [
            {"scheme": "http", "host": "example.com", "ports": [(8000, 9000)]}
        ]
        assert origin_matches_patterns("http://example.com:8000", patterns)
        assert origin_matches_patterns("http://example.com:8500", patterns)
        assert origin_matches_patterns("http://example.com:9000", patterns)
        assert not origin_matches_patterns("http://example.com:9001", patterns)
        assert not origin_matches_patterns("http://example.com", patterns)

    def test_mixed_port_list(self):
        patterns = [
            {"scheme": "http", "host": "example.com", "ports": [81, (8000, 9000)]}
        ]
        assert origin_matches_patterns("http://example.com:81", patterns)
        assert origin_matches_patterns("http://example.com:8080", patterns)
        assert not origin_matches_patterns("http://example.com:80", patterns)


class TestNormalization:
    def test_case_insensitive(self):
        patterns = [{"scheme": "https", "host": "Example.COM"}]
        assert origin_matches_patterns("https://example.com", patterns)
        assert origin_matches_patterns("https://EXAMPLE.COM", patterns)

    def test_trailing_dot(self):
        patterns = [{"scheme": "https", "host": "example.com."}]
        assert origin_matches_patterns("https://example.com", patterns)
        assert origin_matches_patterns("https://example.com.", patterns)

    def test_idna_unicode_pattern_matches_punycode_origin(self):
        patterns = [{"scheme": "https", "host": "bücher.de"}]
        assert origin_matches_patterns("https://xn--bcher-kva.de", patterns)

    def test_idna_punycode_pattern_matches_unicode_origin(self):
        patterns = [{"scheme": "https", "host": "xn--bcher-kva.de"}]
        assert origin_matches_patterns("https://bücher.de", patterns)

    def test_idna_wildcard_subdomain(self):
        patterns = [{"scheme": "https", "host": "*.bücher.de"}]
        assert origin_matches_patterns("https://www.xn--bcher-kva.de", patterns)

    def test_ipv6_literal(self):
        patterns = [{"scheme": "http", "host": "[::1]", "ports": 8000}]
        assert origin_matches_patterns("http://[::1]:8000", patterns)
        assert origin_matches_patterns("http://[0:0:0:0:0:0:0:1]:8000", patterns)
        assert not origin_matches_patterns("http://[::2]:8000", patterns)

    def test_ipv6_no_wildcards(self):
        with pytest.raises(PatternError):
            parse_pattern({"scheme": "http", "host": "[::*]"})

    def test_normalize_host_invalid_ipv6(self):
        assert normalize_host("[::g]") is None


class TestStrictOriginParsing:
    @pytest.mark.parametrize(
        "origin",
        [
            "https://user@a.example.com",
            "https://user:pass@a.example.com",
            "https://a.example.com/path",
            "https://a.example.com?query=1",
            "https://a.example.com#fragment",
            "https://a.example.com https://b.example.com",
            "https://a.example.com:99999",
            "https://a.example.com:abc",
            "https://a.example.com:",
            "null",
            "",
            "a.example.com",
            "https://",
            "https://[::1",
        ],
    )
    def test_invalid_origins_never_match(self, origin):
        patterns = [{"scheme": "*", "host": "**"}]
        assert not origin_matches_patterns(origin, patterns)

    def test_parse_origin_multiple_origins(self):
        assert parse_origin("https://a.com https://b.com") is None

    def test_parse_origin_userinfo(self):
        assert parse_origin("https://user@example.com") is None

    def test_null_not_matched_by_patterns(self):
        patterns = [{"scheme": "*", "host": "**", "ports": [(1, 65535)]}]
        assert not origin_matches_patterns("null", patterns)


class TestPatternValidation:
    @pytest.mark.parametrize(
        "raw",
        [
            "https://example.com",
            {"host": "example.com"},
            {"scheme": "https"},
            {"scheme": "", "host": "example.com"},
            {"scheme": "ht tp", "host": "example.com"},
            {"scheme": "https", "host": ""},
            {"scheme": "https", "host": "exa mple.com"},
            {"scheme": "https", "host": "example..com"},
            {"scheme": "https", "host": "example.com", "ports": 0},
            {"scheme": "https", "host": "example.com", "ports": 65536},
            {"scheme": "https", "host": "example.com", "ports": (9000, 8000)},
            {"scheme": "https", "host": "example.com", "ports": []},
            {"scheme": "https", "host": "example.com", "ports": "8080"},
            {"scheme": "https", "host": "example.com", "ports": True},
            {"scheme": "https", "host": "example.com", "path": "/x"},
        ],
    )
    def test_invalid_patterns_rejected(self, raw):
        with pytest.raises(PatternError):
            parse_pattern(raw)

    def test_invalid_pattern_skipped_at_runtime(self):
        patterns = [
            {"scheme": "https", "host": "example.com", "ports": 0},
            {"scheme": "https", "host": "example.org"},
        ]
        assert origin_matches_patterns("https://example.org", patterns)
        assert not origin_matches_patterns("https://example.com", patterns)
