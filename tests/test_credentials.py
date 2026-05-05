"""Tests for core/credentials.py — CredentialStore unit tests + socket integration."""

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.credentials import (
    CredentialStore,
    _new_access_key_id,
    _prepare_socket_path,
)
from core.models import ClientCred

from conftest import _short_sock_path


# --------------------------------------------------------------------------- #
# _new_access_key_id
# --------------------------------------------------------------------------- #

def test_access_key_id_prefix():
    assert _new_access_key_id().startswith("AKIAPROXY")


def test_access_key_id_length():
    assert len(_new_access_key_id()) == 20


def test_access_key_id_unique():
    ids = {_new_access_key_id() for _ in range(50)}
    assert len(ids) == 50


# --------------------------------------------------------------------------- #
# CredentialStore
# --------------------------------------------------------------------------- #

def test_issue_returns_client_cred():
    store = CredentialStore()
    assert isinstance(store.issue(), ClientCred)


def test_issue_access_key_has_proxy_prefix():
    store = CredentialStore()
    assert store.issue().access_key_id.startswith("AKIAPROXY")


def test_issue_expiry_in_future():
    store = CredentialStore()
    assert store.issue().expiry > datetime.now(timezone.utc)


def test_issue_returns_same_keypair_each_call():
    """Single shared keypair — issue() always returns the same key."""
    store = CredentialStore()
    cred1 = store.issue()
    cred2 = store.issue()
    assert cred1.access_key_id == cred2.access_key_id
    assert cred1.secret_access_key == cred2.secret_access_key


def test_valid_secrets_known_key_returns_secret():
    store = CredentialStore()
    cred = store.issue()
    secrets = store.valid_secrets_for(cred.access_key_id)
    assert secrets == [cred.secret_access_key]


def test_valid_secrets_unknown_key_returns_none():
    store = CredentialStore()
    assert store.valid_secrets_for("AKIAUNKNOWN12345678") is None


def test_different_store_instances_have_different_keypairs():
    """Each CredentialStore generates its own independent keypair in memory."""
    store1 = CredentialStore()
    store2 = CredentialStore()
    # They're independent — store2 cannot validate store1's key
    assert store2.valid_secrets_for(store1.issue().access_key_id) is None


# --------------------------------------------------------------------------- #
# _prepare_socket_path
# --------------------------------------------------------------------------- #

def test_prepare_creates_parent_dirs(tmp_path):
    sock_path = tmp_path / "sub" / "dir" / "creds.sock"
    _prepare_socket_path(sock_path)
    assert sock_path.parent.exists()


def test_prepare_removes_stale_socket():
    sock_path = _short_sock_path()
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(str(sock_path))
    dead.close()
    _prepare_socket_path(sock_path)
    assert not sock_path.exists()


def test_prepare_returns_false_if_live_server_present():
    sock_path = _short_sock_path()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sock_path))
    srv.listen(1)
    try:
        assert _prepare_socket_path(sock_path) is False
    finally:
        srv.close()
        sock_path.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Integration: Unix socket credential server
# --------------------------------------------------------------------------- #

def test_creds_server_returns_valid_json(running_creds_server):
    sock_path, _store = running_creds_server
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(3.0)
        s.connect(str(sock_path))
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    payload = json.loads(data)
    assert payload["Version"] == 1
    assert payload["AccessKeyId"].startswith("AKIAPROXY")
    assert "SecretAccessKey" in payload
    assert "Expiration" in payload


def test_creds_server_returns_same_keypair_each_connection(running_creds_server):
    """All connections get the same shared keypair."""
    sock_path, _store = running_creds_server

    def fetch():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            s.connect(str(sock_path))
            data = b""
            while chunk := s.recv(4096):
                data += chunk
        return json.loads(data)["AccessKeyId"]

    ids = {fetch() for _ in range(5)}
    assert len(ids) == 1  # single shared keypair


def test_creds_server_issued_key_validates(running_creds_server):
    sock_path, store = running_creds_server
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(3.0)
        s.connect(str(sock_path))
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    payload = json.loads(data)
    assert store.valid_secrets_for(payload["AccessKeyId"]) is not None
