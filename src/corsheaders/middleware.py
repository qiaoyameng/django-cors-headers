from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from urllib.parse import SplitResult, urlsplit

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseBase
from django.utils.cache import patch_vary_headers

from corsheaders.conf import conf
from corsheaders.origin_patterns import (
    OriginPattern,
    ParsedOrigin,
    compile_origin_pattern,
    parse_origin,
)
from corsheaders.signals import check_request_enabled

ACCESS_CONTROL_ALLOW_ORIGIN = "access-control-allow-origin"
ACCESS_CONTROL_EXPOSE_HEADERS = "access-control-expose-headers"
ACCESS_CONTROL_ALLOW_CREDENTIALS = "access-control-allow-credentials"
ACCESS_CONTROL_ALLOW_HEADERS = "access-control-allow-headers"
ACCESS_CONTROL_ALLOW_METHODS = "access-control-allow-methods"
ACCESS_CONTROL_MAX_AGE = "access-control-max-age"
ACCESS_CONTROL_REQUEST_PRIVATE_NETWORK = "access-control-request-private-network"
ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK = "access-control-allow-private-network"


class CorsMiddleware:
    sync_capable = True
    async_capable = True

    def __init__(
        self,
        get_response: (
            Callable[[HttpRequest], HttpResponseBase]
            | Callable[[HttpRequest], Awaitable[HttpResponseBase]]
        ),
    ) -> None:
        self.get_response = get_response
        self.async_mode = iscoroutinefunction(self.get_response)
        self._compiled_patterns: tuple[object, tuple[OriginPattern, ...]] | None = None

        if self.async_mode:
            # Mark the class as async-capable, but do the actual switch

            # inside __call__ to avoid swapping out dunder methods
            markcoroutinefunction(self)

    def __call__(
        self, request: HttpRequest
    ) -> HttpResponseBase | Awaitable[HttpResponseBase]:
        if self.async_mode:
            return self.__acall__(request)
        response: HttpResponseBase | None = self.check_preflight(request)
        if response is None:
            result = self.get_response(request)
            assert isinstance(result, HttpResponseBase)
            response = result
        self.add_response_headers(request, response)
        return response

    async def __acall__(self, request: HttpRequest) -> HttpResponseBase:
        response = self.check_preflight(request)
        if response is None:
            result = self.get_response(request)
            assert not isinstance(result, HttpResponseBase)
            response = await result
        self.add_response_headers(request, response)
        return response

    def check_preflight(self, request: HttpRequest) -> HttpResponseBase | None:
        """
        Generate a response for CORS preflight requests.
        """
        request._cors_enabled = self.is_enabled(request)  # type: ignore [attr-defined]
        if (
            request._cors_enabled  # type: ignore [attr-defined]
            and request.method == "OPTIONS"
            and "access-control-request-method" in request.headers
        ):
            return HttpResponse(headers={"content-length": "0"})
        return None

    def add_response_headers(
        self, request: HttpRequest, response: HttpResponseBase
    ) -> HttpResponseBase:
        """
        Add the respective CORS headers
        """
        enabled = getattr(request, "_cors_enabled", None)
        if enabled is None:
            enabled = self.is_enabled(request)

        if not enabled:
            return response

        patch_vary_headers(response, ("origin",))

        origin = request.headers.get("origin")
        if not origin:
            return response

        parsed_origin = parse_origin(origin)
        special_origin = origin in {"null", "file://"}
        if parsed_origin is None and not special_origin:
            return response
        url = None
        if parsed_origin is not None:
            try:
                url = urlsplit(origin)
            except ValueError:
                return response

        if (
            not conf.CORS_ALLOW_ALL_ORIGINS
            and not self.origin_found_in_white_lists(
                origin, url, parsed_origin, special_origin
            )
            and not self.check_signal(request)
        ):
            return response
        if (
            conf.CORS_ALLOW_ALL_ORIGINS
            and origin == "null"
            and origin not in conf.CORS_ALLOWED_ORIGINS
        ):
            return response

        if (
            conf.CORS_ALLOW_ALL_ORIGINS
            and not conf.CORS_ALLOW_CREDENTIALS
            and origin != "null"
        ):
            response[ACCESS_CONTROL_ALLOW_ORIGIN] = "*"
        else:
            response[ACCESS_CONTROL_ALLOW_ORIGIN] = (
                parsed_origin.canonical if parsed_origin is not None else origin
            )

        if conf.CORS_ALLOW_CREDENTIALS:
            response[ACCESS_CONTROL_ALLOW_CREDENTIALS] = "true"

        if len(conf.CORS_EXPOSE_HEADERS):
            response[ACCESS_CONTROL_EXPOSE_HEADERS] = ", ".join(
                conf.CORS_EXPOSE_HEADERS
            )

        if request.method == "OPTIONS":
            response[ACCESS_CONTROL_ALLOW_HEADERS] = ", ".join(conf.CORS_ALLOW_HEADERS)
            response[ACCESS_CONTROL_ALLOW_METHODS] = ", ".join(conf.CORS_ALLOW_METHODS)
            if conf.CORS_PREFLIGHT_MAX_AGE:
                response[ACCESS_CONTROL_MAX_AGE] = str(conf.CORS_PREFLIGHT_MAX_AGE)

        if (
            conf.CORS_ALLOW_PRIVATE_NETWORK
            and request.headers.get(ACCESS_CONTROL_REQUEST_PRIVATE_NETWORK) == "true"
        ):
            response[ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK] = "true"

        return response

    def origin_found_in_white_lists(
        self,
        origin: str,
        url: SplitResult | None,
        parsed_origin: ParsedOrigin | None,
        special_origin: bool,
    ) -> bool:
        if special_origin:
            return origin in conf.CORS_ALLOWED_ORIGINS
        return (
            url is not None
            and (
                self._url_in_whitelist(url, parsed_origin)
                or self.regex_domain_match(origin, parsed_origin)
                or self.origin_pattern_match(parsed_origin)
            )
        )

    def _url_in_whitelist(
        self, url: SplitResult, parsed_origin: ParsedOrigin | None
    ) -> bool:
        if parsed_origin is None:
            return False
        origins = [urlsplit(o) for o in conf.CORS_ALLOWED_ORIGINS]
        return any(
            allowed.scheme == url.scheme and allowed.netloc == url.netloc
            for allowed in origins
        )

    def regex_domain_match(
        self, origin: str, parsed_origin: ParsedOrigin | None
    ) -> bool:
        if parsed_origin is None:
            return False
        return any(
            re.match(domain_pattern, origin)
            for domain_pattern in conf.CORS_ALLOWED_ORIGIN_REGEXES
        )

    def origin_pattern_match(self, parsed_origin: ParsedOrigin | None) -> bool:
        if parsed_origin is None:
            return False
        return any(
            pattern.matches(parsed_origin) for pattern in self._origin_patterns()
        )

    def _origin_patterns(self) -> tuple[OriginPattern, ...]:
        source = tuple(conf.CORS_ALLOWED_ORIGIN_PATTERNS)
        if self._compiled_patterns is None or self._compiled_patterns[0] is not source:
            self._compiled_patterns = (
                source,
                tuple(compile_origin_pattern(pattern) for pattern in source),
            )
        return self._compiled_patterns[1]

    def is_enabled(self, request: HttpRequest) -> bool:
        return bool(
            re.match(conf.CORS_URLS_REGEX, request.path_info)
        ) or self.check_signal(request)

    def check_signal(self, request: HttpRequest) -> bool:
        signal_responses = check_request_enabled.send(sender=None, request=request)
        return any(return_value for function, return_value in signal_responses)
