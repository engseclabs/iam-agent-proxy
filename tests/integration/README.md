# Integration tests

Docker-based integration test stack for iam-agent-proxy. Runs a fully isolated proxy/agent pair using [elhaz](https://github.com/61418/elhaz) as the upstream credential source — useful when the real credentials live in an IAM Identity Center role.

## Prerequisites

- Docker and Docker Compose
- [elhaz](https://github.com/61418/elhaz) installed, daemon running, and the target role added

```bash
elhaz daemon start
elhaz daemon add -n sandbox-elhaz
```

## Start the stack

Run from the **repo root**:

```bash
ELHAZ_CONFIG_NAME=sandbox-elhaz docker compose -f tests/integration/docker-compose.yml up --build proxy
```

## Run the smoke test

```bash
docker compose -f tests/integration/docker-compose.yml run --rm agent aws sts get-caller-identity
```

Expected output:

```json
{
    "UserId": "AROAEXAMPLE:boto3-refresh-session",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/YourRole/boto3-refresh-session"
}
```

A `ServiceUnavailable` response means the proxy can't reach the elhaz daemon — check `elhaz daemon status` and `elhaz daemon list`.

## Interactive agent shell

```bash
docker compose -f tests/integration/docker-compose.yml run --rm agent bash
```

The container has `AWS_PROFILE`, `HTTPS_PROXY`, and `AWS_CA_BUNDLE` pre-configured. Run any AWS commands and watch the proxy terminal for the resolved action stream:

```
[14:32:01] ALLOWED  sts:GetCallerIdentity
[14:32:09] ALLOWED  s3:ListAllMyBuckets
```

## Extract the observed policy

```bash
get-policy
```

## Tear down

```bash
docker compose -f tests/integration/docker-compose.yml down      # keeps volumes
docker compose -f tests/integration/docker-compose.yml down -v   # removes volumes
```

## Configuration

| Env var | Default | Description |
|---|---|---|
| `ELHAZ_CONFIG_NAME` | `sandbox-elhaz` | elhaz config name for the IAC role |
| `ELHAZ_SOCK` | `~/.elhaz/sock/daemon.sock` | Host path to the elhaz daemon socket |
| `ELHAZ_CONFIG_DIR` | `~/.elhaz/configs` | Host path to elhaz config files |
| `ELHAZ_SOCKET_PATH` | `/tmp/elhaz.sock` | Socket path inside the proxy container |
| `PROXY_MODE` | `record` | `record` or `enforce` |
| `ALLOWLIST_PATH` | *(required in enforce mode)* | Path to IAM policy JSON allowlist |

## What's in this directory

```
tests/integration/
  docker-compose.yml     — proxy + agent service definitions
  docker/
    proxy/Dockerfile     — proxy container (proxy.py + elhaz in isolated venv)
    agent/Dockerfile     — agent container (AWS CLI + proxy-creds)
  elhaz.py               — elhaz credential source used by the proxy container
  test_elhaz.py          — unit tests for elhaz.py
  test_resign.sh         — end-to-end smoke test script (run inside agent container)
```

## Running elhaz unit tests locally

The elhaz tests don't require Docker — just the elhaz binary on PATH:

```bash
pytest tests/integration/
```
