"""proxy-creds entry point — credential_process helper for the iam-agent-proxy profile."""

import json
import os
import socket
import sys
from pathlib import Path

SOCK_PATH = Path(
    os.environ.get("PROXY_SOCK_PATH", str(Path.home() / ".iam-agent-proxy" / "creds.sock"))
)
_TIMEOUT = 10.0


def _die(message: str) -> None:
    print(f"proxy-creds: {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if not SOCK_PATH.exists():
        _die(f"socket not found at {SOCK_PATH}")

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(_TIMEOUT)
            s.connect(str(SOCK_PATH))
            data = b""
            while chunk := s.recv(4096):
                data += chunk
    except OSError as exc:
        _die(f"could not connect to {SOCK_PATH}: {exc}")

    try:
        creds = json.loads(data)
    except json.JSONDecodeError as exc:
        _die(f"invalid JSON from socket: {exc}")

    print(json.dumps(creds))
