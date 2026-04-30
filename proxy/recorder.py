"""Request recorder: logs validated, re-signed AWS requests to a JSONL file."""

__all__ = ["RequestRecord", "RequestRecorder"]

import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, ConfigDict

log = logging.getLogger(__name__)

PROXY_MODE = os.environ.get("PROXY_MODE", "record")
PROXY_RECORD_PATH = Path(os.environ.get("PROXY_RECORD_PATH", "./proxy-record.jsonl"))

# Query-protocol services that carry the action in the Action= body/query param.
_QUERY_PROTOCOL_SERVICES = {"sts", "sqs", "sns", "iam", "ec2", "autoscaling", "cloudformation"}


def _parse_action(service: str, method: str, url: str, body: bytes) -> str | None:
    """Derive the AWS API action from the request."""
    if service in _QUERY_PROTOCOL_SERVICES:
        # Try query string first (GET), then body (POST).
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if "Action" in qs:
            return qs["Action"][0]
        if body:
            try:
                body_qs = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
                if "Action" in body_qs:
                    return body_qs["Action"][0]
            except Exception:
                pass
        return None

    # REST-protocol services: derive action from HTTP method + path segments.
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    parts = [p for p in path.split("/") if p]

    _REST_METHOD_MAP = {
        "GET": "Get",
        "PUT": "Put",
        "POST": "Post",
        "DELETE": "Delete",
        "HEAD": "Head",
        "PATCH": "Patch",
        "LIST": "List",
    }
    verb = _REST_METHOD_MAP.get(method.upper(), method.capitalize())

    if service == "s3":
        if not parts:
            return f"{verb}Buckets" if method.upper() == "GET" else verb
        if len(parts) == 1:
            return f"{verb}Bucket"
        return f"{verb}Object"

    # Generic REST: verb + last meaningful path segment (CamelCased).
    if parts:
        segment = parts[-1].replace("-", "_").title().replace("_", "")
        return f"{verb}{segment}"
    return verb


def _parse_resource(service: str, url: str, body: bytes) -> str | None:
    """Extract a resource ARN or identifier from the request, or return None."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    parts = [p for p in path.split("/") if p]

    if service == "s3":
        if not parts:
            return None
        bucket = parts[0]
        if len(parts) == 1:
            return f"arn:aws:s3:::{bucket}"
        key = "/".join(parts[1:])
        return f"arn:aws:s3:::{bucket}/{key}"

    # For query-protocol services check the body/query for resource params.
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if body:
        try:
            body_qs = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
            qs.update(body_qs)
        except Exception:
            pass

    for key in ("RoleArn", "QueueUrl", "TopicArn", "FunctionName", "BucketName", "ResourceArn"):
        if key in qs:
            return qs[key][0]

    return None


class RequestRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str        # ISO 8601
    access_key_id: str
    service: str
    region: str
    action: str | None
    resource: str | None
    method: str
    url: str


class RequestRecorder:
    """Appends RequestRecord entries to a JSONL file in a thread-safe manner."""

    def __init__(self, record_path: Path = PROXY_RECORD_PATH) -> None:
        self._path = record_path
        self._lock = threading.Lock()
        self._enabled = PROXY_MODE == "record"
        if self._enabled:
            log.info("Recording mode enabled; writing to %s", self._path)

    def record(
        self,
        *,
        access_key_id: str,
        service: str,
        region: str,
        method: str,
        url: str,
        body: bytes,
    ) -> None:
        if not self._enabled:
            return

        action = _parse_action(service, method, url, body)
        resource = _parse_resource(service, url, body)

        entry = RequestRecord(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            access_key_id=access_key_id,
            service=service,
            region=region,
            action=action,
            resource=resource,
            method=method,
            url=url,
        )

        line = entry.model_dump_json() + "\n"
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)

        log.info(
            "Recorded request: access_key_id=%s service=%s region=%s action=%s",
            access_key_id, service, region, action,
        )
