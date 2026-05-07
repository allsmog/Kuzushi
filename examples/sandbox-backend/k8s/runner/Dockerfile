# Minimal multi-tool runner image. The k8s-Jobs adapter spawns a Pod
# from this image per `POST /v1/runs`. Bake in the scanners you need;
# the kuzushi client passes the command argv as-is.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        python3 \
        python3-pip \
        python3-venv \
 && rm -rf /var/lib/apt/lists/*

# Semgrep — sufficient for `kuzushi scan` semgrep:scan path.
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir semgrep
ENV PATH="/opt/venv/bin:${PATH}"

# CodeQL CLI — uncomment + tune the version for codeql:scan.
# ARG CODEQL_VERSION=2.20.0
# RUN curl -fsSL "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
#       -o /tmp/codeql.zip \
#  && unzip /tmp/codeql.zip -d /opt && rm /tmp/codeql.zip \
#  && ln -s /opt/codeql/codeql /usr/local/bin/codeql

WORKDIR /workspace
USER 1000:1000

ENTRYPOINT []
CMD ["/bin/sh"]
