"""Tests for proxy/recorder.py — RequestRecord, RequestRecorder, action/resource parsing."""

import json
import threading
from pathlib import Path

import pytest

from proxy.recorder import (
    RequestRecord,
    RequestRecorder,
    _parse_action,
    _parse_resource,
)


# --------------------------------------------------------------------------- #
# _parse_action
# --------------------------------------------------------------------------- #

class TestParseActionQueryProtocol:
    def test_sts_get_caller_identity_from_body(self):
        body = b"Action=GetCallerIdentity&Version=2011-06-15"
        assert _parse_action("sts", "POST", "https://sts.amazonaws.com/", body) == "GetCallerIdentity"

    def test_sqs_send_message_from_body(self):
        body = b"Action=SendMessage&QueueUrl=https%3A%2F%2Fsqs.us-east-1.amazonaws.com%2F123%2Fq"
        assert _parse_action("sqs", "POST", "https://sqs.us-east-1.amazonaws.com/", body) == "SendMessage"

    def test_iam_action_from_query_string(self):
        url = "https://iam.amazonaws.com/?Action=ListRoles&Version=2010-05-08"
        assert _parse_action("iam", "GET", url, b"") == "ListRoles"

    def test_query_protocol_no_action_returns_none(self):
        assert _parse_action("sts", "POST", "https://sts.amazonaws.com/", b"Version=2011-06-15") is None


class TestParseActionRestProtocol:
    def test_s3_get_object(self):
        result = _parse_action("s3", "GET", "https://s3.amazonaws.com/bucket/key", b"")
        assert result == "GetObject"

    def test_s3_put_object(self):
        result = _parse_action("s3", "PUT", "https://s3.amazonaws.com/bucket/key", b"")
        assert result == "PutObject"

    def test_s3_delete_object(self):
        result = _parse_action("s3", "DELETE", "https://s3.amazonaws.com/bucket/key", b"")
        assert result == "DeleteObject"

    def test_s3_get_bucket(self):
        result = _parse_action("s3", "GET", "https://s3.amazonaws.com/bucket", b"")
        assert result == "GetBucket"

    def test_s3_list_buckets(self):
        result = _parse_action("s3", "GET", "https://s3.amazonaws.com/", b"")
        assert result == "GetBuckets"

    def test_generic_rest_head_on_path_segment(self):
        result = _parse_action("lambda", "GET", "https://lambda.us-east-1.amazonaws.com/functions", b"")
        assert result == "GetFunctions"


# --------------------------------------------------------------------------- #
# _parse_resource
# --------------------------------------------------------------------------- #

class TestParseResource:
    def test_s3_object_arn(self):
        result = _parse_resource("s3", "https://s3.amazonaws.com/mybucket/path/to/key", b"")
        assert result == "arn:aws:s3:::mybucket/path/to/key"

    def test_s3_bucket_arn(self):
        result = _parse_resource("s3", "https://s3.amazonaws.com/mybucket", b"")
        assert result == "arn:aws:s3:::mybucket"

    def test_s3_no_bucket_returns_none(self):
        result = _parse_resource("s3", "https://s3.amazonaws.com/", b"")
        assert result is None

    def test_sts_role_arn_from_body(self):
        body = b"Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2FMyRole"
        result = _parse_resource("sts", "https://sts.amazonaws.com/", body)
        assert result == "arn:aws:iam::123456789012:role/MyRole"

    def test_unknown_service_no_resource(self):
        result = _parse_resource("lambda", "https://lambda.us-east-1.amazonaws.com/functions", b"")
        assert result is None


# --------------------------------------------------------------------------- #
# RequestRecord model
# --------------------------------------------------------------------------- #

class TestRequestRecord:
    def test_round_trip_json(self):
        rec = RequestRecord(
            timestamp="2026-01-01T00:00:00Z",
            access_key_id="AKIAPROXYTEST12345678",
            service="s3",
            region="us-east-1",
            action="GetObject",
            resource="arn:aws:s3:::bucket/key",
            method="GET",
            url="https://s3.amazonaws.com/bucket/key",
        )
        data = json.loads(rec.model_dump_json())
        assert data["service"] == "s3"
        assert data["action"] == "GetObject"

    def test_extra_fields_forbidden(self):
        with pytest.raises(Exception):
            RequestRecord(
                timestamp="2026-01-01T00:00:00Z",
                access_key_id="AK",
                service="s3",
                region="us-east-1",
                action=None,
                resource=None,
                method="GET",
                url="https://example.com",
                unexpected_field="x",
            )

    def test_nullable_action_and_resource(self):
        rec = RequestRecord(
            timestamp="2026-01-01T00:00:00Z",
            access_key_id="AK",
            service="s3",
            region="us-east-1",
            action=None,
            resource=None,
            method="GET",
            url="https://s3.amazonaws.com/",
        )
        assert rec.action is None
        assert rec.resource is None


# --------------------------------------------------------------------------- #
# RequestRecorder
# --------------------------------------------------------------------------- #

class TestRequestRecorder:
    def test_writes_jsonl_line(self, tmp_path):
        path = tmp_path / "record.jsonl"
        recorder = RequestRecorder(record_path=path)
        recorder._enabled = True
        recorder.record(
            access_key_id="AKIAPROXYTEST12345678",
            service="sts",
            region="us-east-1",
            method="POST",
            url="https://sts.amazonaws.com/",
            body=b"Action=GetCallerIdentity&Version=2011-06-15",
        )
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["service"] == "sts"
        assert data["region"] == "us-east-1"
        assert data["action"] == "GetCallerIdentity"
        assert data["access_key_id"] == "AKIAPROXYTEST12345678"

    def test_appends_multiple_records(self, tmp_path):
        path = tmp_path / "record.jsonl"
        recorder = RequestRecorder(record_path=path)
        recorder._enabled = True
        for _ in range(3):
            recorder.record(
                access_key_id="AKIAPROXYTEST12345678",
                service="s3",
                region="us-east-1",
                method="GET",
                url="https://s3.amazonaws.com/bucket/key",
                body=b"",
            )
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 3

    def test_disabled_when_mode_not_record(self, tmp_path):
        path = tmp_path / "record.jsonl"
        recorder = RequestRecorder(record_path=path)
        recorder._enabled = False
        recorder.record(
            access_key_id="AK",
            service="s3",
            region="us-east-1",
            method="GET",
            url="https://s3.amazonaws.com/bucket/key",
            body=b"",
        )
        assert not path.exists()

    def test_thread_safe_concurrent_writes(self, tmp_path):
        path = tmp_path / "record.jsonl"
        recorder = RequestRecorder(record_path=path)
        recorder._enabled = True
        n = 50

        def write_record():
            recorder.record(
                access_key_id="AKIAPROXYTEST12345678",
                service="s3",
                region="us-east-1",
                method="GET",
                url="https://s3.amazonaws.com/bucket/key",
                body=b"",
            )

        threads = [threading.Thread(target=write_record) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        lines = path.read_text().strip().splitlines()
        assert len(lines) == n
        # Every line must be valid JSON.
        for line in lines:
            json.loads(line)

    def test_record_contains_timestamp(self, tmp_path):
        path = tmp_path / "record.jsonl"
        recorder = RequestRecorder(record_path=path)
        recorder._enabled = True
        recorder.record(
            access_key_id="AK",
            service="sts",
            region="us-east-1",
            method="POST",
            url="https://sts.amazonaws.com/",
            body=b"Action=GetCallerIdentity",
        )
        data = json.loads(path.read_text().strip())
        assert "T" in data["timestamp"] and data["timestamp"].endswith("Z")

    def test_s3_record_has_resource(self, tmp_path):
        path = tmp_path / "record.jsonl"
        recorder = RequestRecorder(record_path=path)
        recorder._enabled = True
        recorder.record(
            access_key_id="AK",
            service="s3",
            region="us-east-1",
            method="GET",
            url="https://s3.amazonaws.com/mybucket/mykey",
            body=b"",
        )
        data = json.loads(path.read_text().strip())
        assert data["resource"] == "arn:aws:s3:::mybucket/mykey"
