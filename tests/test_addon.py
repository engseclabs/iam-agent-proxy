"""Tests for proxy/addon.py — ElhazResignAddon._handle and request."""

import json

import pytest
from botocore.credentials import Credentials
from mitmproxy.test import tflow

import proxy.addon as addon_mod
from proxy.addon import ElhazResignAddon, _aws_error_response
from proxy.allowlist import Allowlist
from proxy.credentials import CredentialStore
from proxy.exceptions import EnforcementError, UpstreamError, ValidationError
from proxy.resolver import ActionResolver

from conftest import FakeElhazCache, make_signed_flow, make_store_with


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_AUTH_HEADER_NAMES = {"authorization", "x-amz-date", "x-amz-security-token", "x-amz-content-sha256"}


def _make_addon(store: CredentialStore | None = None, elhaz=None, allowlist=None, resolver=None):
    """Build an ElhazResignAddon without starting the real creds server."""
    addon = object.__new__(ElhazResignAddon)
    addon.store = store or make_store_with()
    addon.elhaz = elhaz or FakeElhazCache()
    addon.allowlist = allowlist
    addon.resolver = resolver
    return addon


class _FakeResolver:
    """Stub resolver that returns a fixed action list."""
    def __init__(self, actions: list[str]):
        self._actions = actions

    def resolve(self, **kwargs) -> list[str]:
        return self._actions


# --------------------------------------------------------------------------- #
# _aws_error_response
# --------------------------------------------------------------------------- #

def test_aws_error_response_status_for_validation_error():
    exc = ValidationError("bad token")
    resp = _aws_error_response(exc)
    assert resp.status_code == 403


def test_aws_error_response_status_for_upstream_error():
    exc = UpstreamError("down")
    resp = _aws_error_response(exc)
    assert resp.status_code == 503


def test_aws_error_response_body_is_error_envelope():
    exc = ValidationError("bad token")
    resp = _aws_error_response(exc)
    body = json.loads(resp.content)
    assert body["Error"]["Code"] == "InvalidClientTokenId"
    assert "bad token" in body["Error"]["Message"]


def test_aws_error_response_content_type():
    resp = _aws_error_response(ValidationError("x"))
    assert resp.headers["content-type"] == "application/json"


# --------------------------------------------------------------------------- #
# _handle — validation
# --------------------------------------------------------------------------- #

def test_handle_raises_validation_error_on_bad_sig():
    store = make_store_with(secret="correct")
    addon = _make_addon(store=store)
    flow = make_signed_flow(secret="wrong")
    with pytest.raises(ValidationError):
        addon._handle(flow, "s3", "us-east-1")


def test_handle_raises_upstream_error_when_elhaz_fails():
    store = make_store_with()
    fake_elhaz = FakeElhazCache(raises=RuntimeError("elhaz offline"))
    addon = _make_addon(store=store, elhaz=fake_elhaz)
    flow = make_signed_flow()
    with pytest.raises(UpstreamError):
        addon._handle(flow, "s3", "us-east-1")


# --------------------------------------------------------------------------- #
# _handle — header stripping and re-signing
# --------------------------------------------------------------------------- #

def test_handle_strips_inbound_auth_headers():
    addon = _make_addon()
    flow = make_signed_flow()
    old_auth = flow.request.headers.get("authorization")
    flow.request.headers["x-amz-security-token"] = "oldtoken"
    addon._handle(flow, "s3", "us-east-1")
    assert "x-amz-security-token" not in flow.request.headers
    # authorization must be present but must be the NEW re-signed value
    assert flow.request.headers.get("authorization") != old_auth


def test_handle_adds_new_authorization_header():
    addon = _make_addon()
    flow = make_signed_flow()
    addon._handle(flow, "s3", "us-east-1")
    assert "authorization" in flow.request.headers


def test_handle_new_auth_is_aws_sigv4():
    addon = _make_addon()
    flow = make_signed_flow()
    addon._handle(flow, "s3", "us-east-1")
    assert flow.request.headers["authorization"].startswith("AWS4-HMAC-SHA256 ")


# --------------------------------------------------------------------------- #
# request — non-AWS passthrough
# --------------------------------------------------------------------------- #

def test_request_skips_non_aws_hosts():
    addon = _make_addon()
    flow = tflow.tflow()
    flow.request.host = "example.com"
    flow.request.port = 80
    flow.request.scheme = "http"
    addon.request(flow)
    assert flow.response is None


# --------------------------------------------------------------------------- #
# request — AWS host triggers _handle
# --------------------------------------------------------------------------- #

def test_request_sets_error_response_on_validation_failure():
    store = make_store_with(secret="correct")
    addon = _make_addon(store=store)
    flow = make_signed_flow(secret="wrong")
    # Route through .request() so the ProxyError is caught
    addon.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_request_sets_error_response_on_upstream_failure():
    store = make_store_with()
    fake_elhaz = FakeElhazCache(raises=RuntimeError("elhaz offline"))
    addon = _make_addon(store=store, elhaz=fake_elhaz)
    flow = make_signed_flow()
    addon.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503


def test_request_successful_resign_leaves_no_response_set():
    addon = _make_addon()
    flow = make_signed_flow()
    addon.request(flow)
    assert flow.response is None


# --------------------------------------------------------------------------- #
# Enforcement mode
# --------------------------------------------------------------------------- #

def _make_enforce_addon(allowed_actions: list[str], resolved_actions: list[str]):
    """Build an addon in enforcement mode with a stub resolver."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": allowed_actions, "Resource": "*"}],
    }
    return _make_addon(
        allowlist=Allowlist(policy),
        resolver=_FakeResolver(resolved_actions),
    )


def test_enforcement_permits_allowed_action():
    addon = _make_enforce_addon(["s3:GetObject"], ["s3:GetObject"])
    flow = make_signed_flow()
    addon._handle(flow, "s3", "us-east-1")
    assert flow.response is None


def test_enforcement_blocks_denied_action():
    addon = _make_enforce_addon(["s3:GetObject"], ["s3:DeleteObject"])
    flow = make_signed_flow()
    with pytest.raises(EnforcementError):
        addon._handle(flow, "s3", "us-east-1")


def test_enforcement_blocked_response_is_403():
    addon = _make_enforce_addon(["s3:GetObject"], ["s3:DeleteObject"])
    flow = make_signed_flow()
    addon.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_enforcement_blocked_response_has_access_denied_code():
    addon = _make_enforce_addon(["s3:GetObject"], ["s3:DeleteObject"])
    flow = make_signed_flow()
    addon.request(flow)
    body = json.loads(flow.response.content)
    assert body["Error"]["Code"] == "AccessDenied"


def test_enforcement_permits_empty_action_list():
    # Permissionless operations (empty action list) should always pass
    addon = _make_enforce_addon([], [])
    flow = make_signed_flow()
    addon._handle(flow, "s3", "us-east-1")
    assert flow.response is None


def test_enforcement_permits_wildcard_service():
    addon = _make_enforce_addon(["s3:*"], ["s3:PutObject"])
    flow = make_signed_flow()
    addon._handle(flow, "s3", "us-east-1")
    assert flow.response is None


def test_enforcement_blocks_multi_action_if_any_denied():
    # CopyObject requires multiple actions; if any are denied, block the request
    addon = _make_enforce_addon(["s3:GetObject"], ["s3:GetObject", "s3:PutObject"])
    flow = make_signed_flow()
    with pytest.raises(EnforcementError):
        addon._handle(flow, "s3", "us-east-1")


def test_aws_error_response_status_for_enforcement_error():
    exc = EnforcementError("not allowed")
    resp = _aws_error_response(exc)
    assert resp.status_code == 403


def test_aws_error_response_code_for_enforcement_error():
    exc = EnforcementError("not allowed")
    resp = _aws_error_response(exc)
    body = json.loads(resp.content)
    assert body["Error"]["Code"] == "AccessDenied"
