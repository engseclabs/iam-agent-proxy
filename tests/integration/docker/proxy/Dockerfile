FROM python:3.12-slim

# proxy.py and elhaz have an irreconcilable typing-extensions version conflict.
# Install proxy.py (and the rest of the proxy stack) in the default environment,
# then install elhaz in an isolated venv and symlink its binary onto PATH.
RUN pip install --no-cache-dir "proxy.py" botocore pydantic cryptography && \
    python -m venv /opt/elhaz-venv && \
    /opt/elhaz-venv/bin/pip install --no-cache-dir elhaz==0.5.1 && \
    ln -s /opt/elhaz-venv/bin/elhaz /usr/local/bin/elhaz

WORKDIR /proxy

COPY iam_agent_proxy.py .
COPY core/ core/
COPY tests/integration/elhaz.py core/elhaz.py
COPY docs/map.json docs/map.json

ENV PROXY_SOCK_PATH=/run/proxy/creds.sock
ENV ELHAZ_SOCKET_PATH=/tmp/elhaz.sock

EXPOSE 8080

CMD ["sh", "-c", \
  "mkdir -p /run/proxy && \
   python -m iam_agent_proxy"]
