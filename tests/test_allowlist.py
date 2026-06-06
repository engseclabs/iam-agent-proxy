"""Tests for proxy/allowlist.py — Allowlist policy checking."""

import json
import pytest
from pathlib import Path

from core.allowlist import Allowlist


def _make(actions):
    """Build an Allowlist from a list of action strings."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    }
    return Allowlist(policy)


# --------------------------------------------------------------------------- #
# Basic permit / deny
# --------------------------------------------------------------------------- #

def test_exact_action_permitted():
    al = _make(["s3:GetObject"])
    assert al.permits(["s3:GetObject"])


def test_exact_action_denied():
    al = _make(["s3:GetObject"])
    assert not al.permits(["s3:PutObject"])


def test_case_insensitive_match():
    al = _make(["S3:GetObject"])
    assert al.permits(["s3:getobject"])
    assert al.permits(["S3:GetObject"])


def test_empty_action_list_always_permitted():
    al = _make([])
    assert al.permits([])


def test_all_actions_must_be_permitted():
    al = _make(["s3:GetObject", "s3:PutObject"])
    assert al.permits(["s3:GetObject", "s3:PutObject"])
    assert not al.permits(["s3:GetObject", "s3:DeleteObject"])


# --------------------------------------------------------------------------- #
# Wildcard matching
# --------------------------------------------------------------------------- #

def test_service_wildcard():
    al = _make(["s3:*"])
    assert al.permits(["s3:GetObject"])
    assert al.permits(["s3:PutObject"])
    assert not al.permits(["ec2:DescribeInstances"])


def test_global_wildcard():
    al = _make(["*"])
    assert al.permits(["s3:GetObject"])
    assert al.permits(["iam:CreateRole"])
    assert al.permits(["anything:whatever"])


def test_action_string_not_list():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    al = Allowlist(policy)
    assert al.permits(["s3:GetObject"])


# --------------------------------------------------------------------------- #
# Deny statements are ignored
# --------------------------------------------------------------------------- #

def test_deny_statements_ignored():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
            {"Effect": "Deny",  "Action": ["s3:GetObject"], "Resource": "*"},
        ],
    }
    al = Allowlist(policy)
    # Deny is not evaluated; only Allow statements matter
    assert al.permits(["s3:GetObject"])


# --------------------------------------------------------------------------- #
# from_file
# --------------------------------------------------------------------------- #

def test_from_file(tmp_path):
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "*"}],
    }
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(policy))
    al = Allowlist.from_file(p)
    assert al.permits(["kms:Decrypt"])
    assert not al.permits(["kms:GenerateDataKey"])


# --------------------------------------------------------------------------- #
# Multiple statements
# --------------------------------------------------------------------------- #

def test_multiple_statements_unioned():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["kms:Decrypt"],  "Resource": "*"},
        ],
    }
    al = Allowlist(policy)
    assert al.permits(["s3:GetObject"])
    assert al.permits(["kms:Decrypt"])
    assert al.permits(["s3:GetObject", "kms:Decrypt"])
    assert not al.permits(["s3:PutObject"])


# --------------------------------------------------------------------------- #
# empty / load_or_empty
# --------------------------------------------------------------------------- #

def test_empty_permits_nothing():
    al = Allowlist.empty()
    assert not al.permits(["s3:GetObject"])
    assert al.permits([])  # permissionless op still allowed


def test_load_or_empty_missing_file(tmp_path):
    al = Allowlist.load_or_empty(tmp_path / "nope.json")
    assert not al.permits(["s3:GetObject"])


def test_load_or_empty_existing_file(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
    }))
    al = Allowlist.load_or_empty(p)
    assert al.permits(["s3:GetObject"])


# --------------------------------------------------------------------------- #
# add_actions / writer
# --------------------------------------------------------------------------- #

def test_add_actions_grows_allow_set():
    al = Allowlist.empty()
    assert al.add_actions(["s3:GetObject"]) is True
    assert al.permits(["s3:GetObject"])


def test_add_actions_returns_false_when_nothing_new():
    al = _make(["s3:GetObject"])
    assert al.add_actions(["s3:GetObject"]) is False
    # Case-insensitive: already covered, so still no change.
    assert al.add_actions(["S3:GETOBJECT"]) is False


def test_add_actions_partial_change_returns_true():
    al = _make(["s3:GetObject"])
    assert al.add_actions(["s3:GetObject", "s3:PutObject"]) is True
    assert al.permits(["s3:PutObject"])


def test_to_policy_preserves_original_casing():
    al = Allowlist.empty()
    al.add_actions(["s3:GetObject", "kms:Decrypt"])
    policy = al.to_policy()
    actions = policy["Statement"][0]["Action"]
    assert "s3:GetObject" in actions
    assert "kms:Decrypt" in actions
    # sorted, IAM-shaped
    assert policy["Version"] == "2012-10-17"
    assert policy["Statement"][0]["Effect"] == "Allow"
    assert policy["Statement"][0]["Resource"] == "*"


def test_to_policy_round_trips_through_allowlist():
    al = Allowlist.empty()
    al.add_actions(["s3:GetObject", "ec2:DescribeInstances"])
    reloaded = Allowlist(al.to_policy())
    assert reloaded.permits(["s3:GetObject", "ec2:DescribeInstances"])
    assert not reloaded.permits(["s3:PutObject"])


def test_save_writes_loadable_policy(tmp_path):
    al = Allowlist.empty()
    al.add_actions(["s3:GetObject"])
    p = tmp_path / "sub" / "policy.json"  # parent dir does not exist yet
    al.save(p)
    assert p.exists()
    reloaded = Allowlist.from_file(p)
    assert reloaded.permits(["s3:GetObject"])
    # File is valid JSON in IAM shape.
    doc = json.loads(p.read_text())
    assert doc["Statement"][0]["Action"] == ["s3:GetObject"]


def test_save_then_add_then_save_accumulates(tmp_path):
    p = tmp_path / "policy.json"
    al = Allowlist.empty()
    al.add_actions(["s3:GetObject"])
    al.save(p)
    al.add_actions(["s3:PutObject"])
    al.save(p)
    reloaded = Allowlist.from_file(p)
    assert reloaded.permits(["s3:GetObject", "s3:PutObject"])


def test_wildcard_preserved_through_save(tmp_path):
    p = tmp_path / "policy.json"
    al = _make(["s3:*"])
    al.save(p)
    reloaded = Allowlist.from_file(p)
    assert reloaded.permits(["s3:GetObject"])
    assert not reloaded.permits(["ec2:DescribeInstances"])
