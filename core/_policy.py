"""get-policy entry point — reads the action log and emits a least-privilege IAM policy."""

import json
import os
import sys
from pathlib import Path

ACTION_LOG = Path(
    os.environ.get("ACTION_LOG_PATH", str(Path.home() / ".iam-agent-proxy" / "actions.log"))
)


def main() -> None:
    if not ACTION_LOG.exists():
        print(
            f"No action log found at {ACTION_LOG}\n"
            "Make sure the proxy is running and you have made some AWS calls.",
            file=sys.stderr,
        )
        sys.exit(1)

    actions = sorted({line.strip() for line in ACTION_LOG.read_text().splitlines() if line.strip()})

    if not actions:
        print("Action log is empty. Run some AWS commands first.", file=sys.stderr)
        sys.exit(1)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ProxyRecordedActions",
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*",
            }
        ],
    }

    print(json.dumps(policy, indent=2))
