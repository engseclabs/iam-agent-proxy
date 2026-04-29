# aws-sigv4-resigning-proxy

A [mitmproxy](https://mitmproxy.org/) addon that sits between an untrusted agent and AWS. The agent holds a proxy-issued keypair that has no IAM identity. The proxy validates the inbound SigV4 signature locally, strips it, and re-signs outbound requests with real IAC credentials the agent never sees.

## Why this exists: IAM Identity Center roles are unmodifiable

AWS IAM Identity Center roles live under `/aws-reserved/` and return `UnmodifiableEntity` on any attempt to modify their trust policy. The trust policy allows only `sts:AssumeRoleWithSAML` from the SAML provider — self-assumption is blocked. Session policies (which require an `AssumeRole` call the trust policy must permit) are also unreachable.

The proxy is the workaround: it holds an [elhaz](https://github.com/61418/elhaz) session for the IAC role and re-signs outbound requests. The agent authenticates to the proxy, not to AWS directly.

## How it works

**Credential carrier** — at startup, the proxy generates fake-but-syntactically-valid AWS keypairs and vends them to agent clients over a Unix socket (`creds.sock`). There is no IAM identity behind these keys. The agent's AWS SDK uses them to sign requests; the proxy validates the signature and re-signs with real credentials. If the keypair leaks, it is useless to AWS.

Each socket connection gets its own distinct keypair, so the proxy can tell clients apart by their `access_key_id`.

**Local SigV4 validation** — the proxy recomputes the HMAC-SHA256 signature from the inbound request and compares it against the `Authorization` header. Requests signed with unknown or mismatched keys are rejected with a forged `InvalidClientTokenId` 403 before any IAC credential fetch occurs.

**Docker isolation** — the agent container gets only `creds.sock` and the mitmproxy port. No elhaz socket, no IAM instance profile, no host network access. The proxy is the agent's only path to AWS. Isolation is a property of the environment, not a property of the agent.

**Recording and enforcement modes** *(planned)*

- **Recording mode**: forward all validated requests, log every AWS API call (service, action, resource ARN).
- **Enforcement mode**: check each request against an allowlist derived from a prior recording. Block everything else with a forged `AccessDenied` 403 that AWS SDKs handle on their normal error path.

This inverts the least-privilege problem: observe real behavior first, then derive the allowlist from it. See [DESIGN.md](DESIGN.md) for the full architecture.

## Prerequisites

- [elhaz](https://github.com/61418/elhaz) installed and daemon running
- A named elhaz config for the role you want the agent to use
- Python 3.12

## Quickstart

```bash
# 1. Create the virtualenv
bash setup_venv.sh

# 2. Start the proxy (in a separate terminal)
#    Creates /run/proxy/creds.sock and starts listening on port 8080
ELHAZ_CONFIG_NAME=my-agent-role bash start_proxy.sh

# 3. Run the test
#    Fetches a proxy-issued keypair from creds.sock, signs a request with it,
#    and verifies the proxy re-signs and forwards it correctly
bash test_resign.sh
```

The test calls `aws sts get-caller-identity` through the proxy. The returned ARN should be the elhaz role, not whatever identity is in your shell environment.

## Agent setup

The agent container fetches its keypair via the `credential_process` mechanism — no custom SDK code required.

Install `proxy-creds` in the container:

```bash
cp proxy-creds /usr/local/bin/proxy-creds
chmod +x /usr/local/bin/proxy-creds
```

Add to `~/.aws/config` in the container:

```ini
[profile proxy]
credential_process = /usr/local/bin/proxy-creds
```

Mount only `creds.sock` into the container (not the elhaz socket or any IAC credentials):

```
/run/proxy/creds.sock  →  mounted into agent container
/run/proxy/mitm.sock   →  proxy side only
```

## Configuration

| Env var | Default | Description |
|---|---|---|
| `ELHAZ_CONFIG_NAME` | `sandbox-elhaz` | elhaz config name for the IAC role |
| `PROXY_SOCK_PATH` | `/run/proxy/creds.sock` | Unix socket path for credential vending |
| `PROXY_KEYPAIR_TTL` | `3600` | Keypair lifetime in seconds |

## Files

| File | What it does |
|---|---|
| `elhaz_resign.py` | mitmproxy addon — issues per-client keypairs, validates inbound SigV4, re-signs with elhaz credentials |
| `proxy-creds` | `credential_process` helper — connects to `creds.sock` and prints the keypair JSON the AWS SDK expects |
| `setup_venv.sh` | Creates a `venv/` with mitmproxy and botocore |
| `start_proxy.sh` | Starts `mitmdump` on port 8080 with the addon loaded |
| `test_resign.sh` | Fetches a proxy keypair and calls `aws sts get-caller-identity` through the proxy |
| `DESIGN.md` | Full architecture and design rationale |
