"""Per-client credential store and Unix socket credential server."""

__all__ = ["CredentialStore", "start_creds_server"]

import logging
import os
import secrets
import socket
import string
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .exceptions import ProxyError
from .models import ClientCred, CredentialPayload

log = logging.getLogger(__name__)

_AK_PREFIX = "AKIAPROXY"
_AK_ALPHABET = string.ascii_uppercase + string.digits

PROXY_KEYPAIR_TTL = int(os.environ.get("PROXY_KEYPAIR_TTL", "3600"))


def _new_access_key_id() -> str:
    suffix = "".join(secrets.choice(_AK_ALPHABET) for _ in range(20 - len(_AK_PREFIX)))
    return _AK_PREFIX + suffix


# --------------------------------------------------------------------------- #
# Credential store
# --------------------------------------------------------------------------- #

class CredentialStore:
    """Single shared keypair for the proxy lifetime.

    The keypair is stored in environment variables so all worker processes
    (forked by proxy.py) can validate requests without IPC. The creds socket
    serves this same keypair to every client that connects.
    """

    _ENV_KEY = "_PROXY_CRED_KEY"
    _ENV_SECRET = "_PROXY_CRED_SECRET"
    _ENV_EXPIRY = "_PROXY_CRED_EXPIRY"

    def __init__(self) -> None:
        # Generate once on construction; inherited by forked workers via env.
        if self._ENV_KEY not in os.environ:
            cred = self._generate()
            os.environ[self._ENV_KEY] = cred.access_key_id
            os.environ[self._ENV_SECRET] = cred.secret_access_key
            os.environ[self._ENV_EXPIRY] = cred.expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
            log.info("Issued proxy keypair access_key_id=%s expiry=%s",
                     cred.access_key_id, cred.expiry)

    def _generate(self) -> ClientCred:
        return ClientCred(
            access_key_id=_new_access_key_id(),
            secret_access_key=secrets.token_hex(32),
            expiry=datetime.now(timezone.utc) + timedelta(seconds=PROXY_KEYPAIR_TTL),
        )

    def issue(self) -> ClientCred:
        """Return the current keypair (same for every caller)."""
        return ClientCred(
            access_key_id=os.environ[self._ENV_KEY],
            secret_access_key=os.environ[self._ENV_SECRET],
            expiry=datetime.fromisoformat(os.environ[self._ENV_EXPIRY]),
        )

    def valid_secrets_for(self, access_key_id: str) -> list[str] | None:
        """Return the secret if access_key_id matches the current keypair."""
        if access_key_id == os.environ.get(self._ENV_KEY):
            return [os.environ[self._ENV_SECRET]]
        return None


# --------------------------------------------------------------------------- #
# Unix socket credential server
# --------------------------------------------------------------------------- #

def _prepare_socket_path(sock_path: Path) -> bool:
    """Remove a stale socket file if present.

    Returns True if the caller should proceed to bind, False if a live server
    is already listening there (another worker beat us to it — skip quietly).
    """
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    if not sock_path.exists():
        return True
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(str(sock_path))
        # A live server is already bound — another worker owns it.
        return False
    except ConnectionRefusedError:
        sock_path.unlink()
        return True
    except FileNotFoundError:
        return True
    finally:
        probe.close()


def _serve_creds(sock_path: Path, store: CredentialStore) -> None:
    """Issue a fresh keypair per connection and send it to the client (blocking)."""
    if not _prepare_socket_path(sock_path):
        log.debug("Credential server already running at %s, skipping", sock_path)
        return

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(str(sock_path))
        sock_path.chmod(0o600)
        srv.listen()
        log.info("Credential socket listening at %s", sock_path)
        while True:
            try:
                conn, _ = srv.accept()
                with conn:
                    payload = store.issue().to_payload()
                    conn.sendall(payload.model_dump_json().encode())
            except Exception as exc:
                log.error("creds.sock error: %s", exc)


def start_creds_server(sock_path: Path, store: CredentialStore) -> None:
    t = threading.Thread(target=_serve_creds, args=(sock_path, store), daemon=True)
    t.start()
