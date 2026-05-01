"""mitmproxy addon: the ElhazResignAddon entry point."""

__all__ = ["ElhazResignAddon", "load", "addons"]

import logging
import os
from pathlib import Path

from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
from mitmproxy import http

from .allowlist import Allowlist
from .credentials import CredentialStore, start_creds_server
from .elhaz import ELHAZ_CONFIG, ElhazCredentialCache
from .exceptions import EnforcementError, ProxyError, UpstreamError, ValidationError, error_status
from .models import ErrorEnvelope
from .resolver import load_resolver
from .sigv4 import parse_aws_host, validate_sigv4

log = logging.getLogger(__name__)

PROXY_SOCK_PATH = Path(os.environ.get("PROXY_SOCK_PATH", "/run/proxy/creds.sock"))

# PROXY_MODE: "record" (default) or "enforce"
_PROXY_MODE = os.environ.get("PROXY_MODE", "record").lower()
# ALLOWLIST_PATH: path to IAM policy JSON used in enforce mode
_ALLOWLIST_PATH = os.environ.get("ALLOWLIST_PATH", "")


def _load_allowlist() -> Allowlist | None:
    if _PROXY_MODE != "enforce":
        return None
    if not _ALLOWLIST_PATH:
        raise RuntimeError("PROXY_MODE=enforce requires ALLOWLIST_PATH to be set")
    path = Path(_ALLOWLIST_PATH)
    if not path.exists():
        raise RuntimeError(f"ALLOWLIST_PATH {path} does not exist")
    log.info("Enforcement mode: loading allowlist from %s", path)
    return Allowlist.from_file(path)

_AUTH_HEADERS = {
    "authorization",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
}


def _aws_error_response(exc: ProxyError) -> http.Response:
    body = ErrorEnvelope.from_exc(exc.code, str(exc)).model_dump_json()
    return http.Response.make(
        error_status(exc),
        body,
        {"Content-Type": "application/json"},
    )


class ElhazResignAddon:
    def __init__(self) -> None:
        self.store = CredentialStore()
        self.elhaz = ElhazCredentialCache(ELHAZ_CONFIG)
        self.allowlist: Allowlist | None = _load_allowlist()
        self.resolver = load_resolver() if _PROXY_MODE == "enforce" else None
        start_creds_server(PROXY_SOCK_PATH, self.store)
        log.info("Proxy mode: %s", _PROXY_MODE)

    def request(self, flow: http.HTTPFlow) -> None:
        parsed = parse_aws_host(flow.request.pretty_host)
        if parsed is None:
            return

        service, region = parsed
        log.info(
            "Intercepted AWS request: host=%s service=%s region=%s method=%s",
            flow.request.pretty_host, service, region, flow.request.method,
        )

        try:
            self._handle(flow, service, region)
        except ProxyError as exc:
            log.warning("Rejected request: %s", exc)
            flow.response = _aws_error_response(exc)

    def _handle(self, flow: http.HTTPFlow, service: str, region: str) -> None:
        if not validate_sigv4(flow, self.store):
            raise ValidationError("The security token included in the request is invalid.")

        if self.allowlist is not None and self.resolver is not None:
            self._enforce(flow, service)

        for h in list(flow.request.headers.keys()):
            if h.lower() in _AUTH_HEADERS:
                del flow.request.headers[h]

        try:
            creds = self.elhaz.get()
        except Exception as exc:
            raise UpstreamError("Proxy could not obtain IAC credentials.") from exc

        aws_request = AWSRequest(
            method=flow.request.method,
            url=flow.request.pretty_url,
            data=flow.request.content or b"",
            headers=dict(flow.request.headers),
        )
        auth_cls = S3SigV4Auth if service == "s3" else SigV4Auth
        auth_cls(creds, service, region).add_auth(aws_request)
        for key, value in aws_request.headers.items():
            flow.request.headers[key] = value

        log.info("Request re-signed for %s/%s", service, region)

    def _enforce(self, flow: http.HTTPFlow, service: str) -> None:
        """Resolve the request to IAM actions and block if not in the allowlist."""
        req = flow.request
        actions = self.resolver.resolve(  # type: ignore[union-attr]
            method=req.method,
            host=req.pretty_host,
            path=req.path,
            headers=dict(req.headers),
            body=req.content or b"",
            service_slug=service,
        )
        log.info("Resolved actions for %s %s: %s", req.method, req.path, actions)

        if not self.allowlist.permits(actions):  # type: ignore[union-attr]
            denied = actions[0] if actions else f"{service}:Unknown"
            raise EnforcementError(
                f"User is not authorized to perform: {denied} "
                f"(proxy enforcement mode)"
            )


def load(loader) -> None:  # noqa: D103 — mitmproxy hook
    pass


addons = [ElhazResignAddon()]
