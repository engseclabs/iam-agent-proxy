FROM python:3.12-slim

RUN pip install --no-cache-dir awscli

WORKDIR /agent

COPY proxy_creds.py /usr/local/bin/proxy_creds.py
COPY get_policy.py /usr/local/bin/get_policy.py

COPY tests/integration/test_resign.sh /agent/test_resign.sh
RUN chmod +x /agent/test_resign.sh

# AWS CLI config: use proxy-creds for the "proxy" profile.
# HTTPS_PROXY and AWS_CA_BUNDLE are injected by docker-compose.
RUN mkdir -p /root/.aws && printf '\
[profile proxy]\n\
credential_process = python /usr/local/bin/proxy_creds.py\n\
region = us-east-1\n' > /root/.aws/config

ENV AWS_PROFILE=proxy
ENV PROXY_SOCK_PATH=/run/proxy/creds.sock
ENV ACTION_LOG_PATH=/run/proxy/actions.log

CMD ["/bin/bash"]
