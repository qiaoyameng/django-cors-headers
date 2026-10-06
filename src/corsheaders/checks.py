from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from django.conf import settings
from django.core.checks import CheckMessage, Error

from corsheaders.conf import conf
from corsheaders.origin_patterns import (
    OriginPatternError,
    compile_origin_pattern,
    parse_origin,
)


def check_settings(**kwargs: Any) -> list[CheckMessage]:
    errors: list[CheckMessage] = []

    if not is_sequence(conf.CORS_ALLOW_HEADERS, str):
        errors.append(
            Error(
                "CORS_ALLOW_HEADERS should be a sequence of strings.",
                id="corsheaders.E001",
            )
        )

    if not is_sequence(conf.CORS_ALLOW_METHODS, str):
        errors.append(
            Error(
                "CORS_ALLOW_METHODS should be a sequence of strings.",
                id="corsheaders.E002",
            )
        )

    if not isinstance(conf.CORS_ALLOW_CREDENTIALS, bool):
        errors.append(  # type: ignore [unreachable]
            Error("CORS_ALLOW_CREDENTIALS should be a bool.", id="corsheaders.E003")
        )

    if not isinstance(conf.CORS_ALLOW_PRIVATE_NETWORK, bool):
        errors.append(  # type: ignore [unreachable]
            Error(
                "CORS_ALLOW_PRIVATE_NETWORK should be a bool.",
                id="corsheaders.E015",
            )
        )

    if (
        not isinstance(conf.CORS_PREFLIGHT_MAX_AGE, int)  # type: ignore [redundant-expr]
        or conf.CORS_PREFLIGHT_MAX_AGE < 0
    ):
        errors.append(
            Error(
                (
                    "CORS_PREFLIGHT_MAX_AGE should be an integer greater than "
                    + "or equal to zero."
                ),
                id="corsheaders.E004",
            )
        )

    if not isinstance(conf.CORS_ALLOW_ALL_ORIGINS, bool):
        if hasattr(settings, "CORS_ALLOW_ALL_ORIGINS"):  # type: ignore [unreachable]
            allow_all_alias = "CORS_ALLOW_ALL_ORIGINS"
        else:
            allow_all_alias = "CORS_ORIGIN_ALLOW_ALL"
        errors.append(
            Error(
                f"{allow_all_alias} should be a bool.",
                id="corsheaders.E005",
            )
        )

    if hasattr(settings, "CORS_ALLOWED_ORIGINS"):
        allowed_origins_alias = "CORS_ALLOWED_ORIGINS"
    else:
        allowed_origins_alias = "CORS_ORIGIN_WHITELIST"

    if not is_sequence(conf.CORS_ALLOWED_ORIGINS, str):
        errors.append(
            Error(
                f"{allowed_origins_alias} should be a sequence of strings.",
                id="corsheaders.E006",
            )
        )
    else:
        special_origin_values = (
            # From 'security sensitive' contexts
            "null",
            # From files on Chrome on Android
            # https://bugs.chromium.org/p/chromium/issues/detail?id=991107
            "file://",
        )
        for origin in conf.CORS_ALLOWED_ORIGINS:
            if origin in special_origin_values:
                continue
            parsed = urlsplit(origin)
            has_invalid_origin_part = False
            if parsed.scheme == "" or parsed.netloc == "":
                has_invalid_origin_part = True
                errors.append(
                    Error(
                        f"Origin {repr(origin)} in {allowed_origins_alias} is missing scheme or netloc",
                        id="corsheaders.E013",
                        hint=(
                            "Add a scheme (e.g. https://) or netloc (e.g. "
                            + "example.com)."
                        ),
                    )
                )
            else:
                for part in ("path", "query", "fragment"):
                    if getattr(parsed, part) != "":
                        has_invalid_origin_part = True
                        errors.append(
                            Error(
                                f"Origin {repr(origin)} in {allowed_origins_alias} should not have {part}",
                                id="corsheaders.E014",
                            )
                        )

            if (
                not has_invalid_origin_part
                and (parsed.username is not None or parse_origin(origin) is None)
            ):
                errors.append(
                    Error(
                        f"Origin {repr(origin)} in {allowed_origins_alias} is not a valid origin",
                        id="corsheaders.E013",
                    )
                )

    if hasattr(settings, "CORS_ALLOWED_ORIGIN_REGEXES"):
        allowed_regexes_alias = "CORS_ALLOWED_ORIGIN_REGEXES"
    else:
        allowed_regexes_alias = "CORS_ORIGIN_REGEX_WHITELIST"
    if not is_sequence(conf.CORS_ALLOWED_ORIGIN_REGEXES, (str, re.Pattern)):
        errors.append(
            Error(
                f"{allowed_regexes_alias} should be a sequence of strings and/or compiled regexes.",
                id="corsheaders.E007",
            )
        )

    if not isinstance(conf.CORS_ALLOWED_ORIGIN_PATTERNS, Sequence) or isinstance(
        conf.CORS_ALLOWED_ORIGIN_PATTERNS, (str, bytes)
    ) or not all(
        isinstance(pattern, Mapping)
        for pattern in conf.CORS_ALLOWED_ORIGIN_PATTERNS
    ):
        errors.append(
            Error(
                "CORS_ALLOWED_ORIGIN_PATTERNS should be a sequence of mappings.",
                id="corsheaders.E016",
            )
        )
    else:
        compiled_patterns = []
        for index, pattern in enumerate(conf.CORS_ALLOWED_ORIGIN_PATTERNS):
            try:
                compiled_pattern = compile_origin_pattern(pattern)
            except OriginPatternError as exc:
                errors.append(
                    Error(
                        (
                            "Origin pattern at index "
                            f"{index} in CORS_ALLOWED_ORIGIN_PATTERNS is invalid: "
                            f"{exc}"
                        ),
                        id="corsheaders.E016",
                    )
                )
            else:
                compiled_patterns.append((index, compiled_pattern))

        seen_patterns: set[tuple[object, ...]] = set()
        for index, pattern in compiled_patterns:
            signature = (
                pattern.scheme,
                pattern.host,
                pattern.wildcard,
                pattern.is_ipv6,
                pattern.port_range,
            )
            if signature in seen_patterns:
                errors.append(
                    Error(
                        (
                            "Origin pattern at index "
                            f"{index} in CORS_ALLOWED_ORIGIN_PATTERNS duplicates an earlier pattern"
                        ),
                        id="corsheaders.E017",
                    )
                )
            else:
                seen_patterns.add(signature)

    if not is_sequence(conf.CORS_EXPOSE_HEADERS, str):
        errors.append(
            Error("CORS_EXPOSE_HEADERS should be a sequence.", id="corsheaders.E008")
        )

    if not isinstance(conf.CORS_URLS_REGEX, (str, re.Pattern)):
        errors.append(  # type: ignore [unreachable]
            Error("CORS_URLS_REGEX should be a string or regex.", id="corsheaders.E009")
        )

    if hasattr(settings, "CORS_MODEL"):
        errors.append(
            Error(
                (
                    "The CORS_MODEL setting has been removed - see "
                    + "django-cors-headers' HISTORY."
                ),
                id="corsheaders.E012",
            )
        )

    if hasattr(settings, "CORS_REPLACE_HTTPS_REFERER"):
        errors.append(
            Error(
                (
                    "The CORS_REPLACE_HTTPS_REFERER setting has been removed"
                    + " - see django-cors-headers' CHANGELOG."
                ),
                id="corsheaders.E013",
            )
        )

    return errors


def is_sequence(thing: Any, type_or_types: type[Any] | tuple[type[Any], ...]) -> bool:
    return (
        isinstance(thing, Sequence)
        and not isinstance(thing, (str, bytes))
        and all(isinstance(x, type_or_types) for x in thing)
    )
