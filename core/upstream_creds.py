"""boto3-based upstream credential source for the native (non-Docker) path."""

__all__ = ["BotoCredentialSource"]

import os

import boto3
from botocore.credentials import Credentials

# Profile name to use for re-signing. Defaults to "iam-agent-proxy" so the
# proxy never silently consumes [default] credentials.
_PROFILE_NAME = os.environ.get("AWS_PROXY_PROFILE", "iam-agent-proxy")


class BotoCredentialSource:
    """Fetches real AWS credentials from a named AWS profile.

    Holds a single boto3.Session for the lifetime of the proxy so that
    botocore's RefreshableCredentials machinery can refresh expiring credentials
    (SSO, instance profiles, assumed roles) without re-running provider
    discovery from scratch on every request.
    """

    def __init__(self, profile_name: str = _PROFILE_NAME) -> None:
        self._session = boto3.Session(profile_name=profile_name)

    def get(self) -> Credentials:
        creds = self._session.get_credentials().get_frozen_credentials()
        return Credentials(creds.access_key, creds.secret_key, creds.token)
