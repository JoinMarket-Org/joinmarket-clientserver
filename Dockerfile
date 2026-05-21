ARG BITCOIN_VERSION=29.2
ARG PYTHON_IMAGE_TAG=3.13-slim-trixie
FROM bitcoin/bitcoin:${BITCOIN_VERSION} AS bitcoin
FROM python:${PYTHON_IMAGE_TAG} AS python
WORKDIR /jm/clientserver

FROM python AS base-deps
RUN DEBIAN_FRONTEND=noninteractive \
  apt-get update \
  && apt-get install -y --no-install-recommends \
    libsecp256k1-2 \
    libsodium23 \
    openssl \
    tor \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

FROM base-deps AS builder
COPY . .
RUN python -m venv jmvenv \
  && . ./jmvenv/bin/activate \
  && pip install -e .[services]

FROM base-deps AS base
COPY --from=builder /jm/clientserver /jm/clientserver
ENTRYPOINT ["./scripts/docker-entrypoint.sh"]

FROM base AS test
ARG BITCOIN_VERSION
COPY --from=bitcoin /opt/bitcoin-${BITCOIN_VERSION}/bin /usr/local/bin/
RUN . ./jmvenv/bin/activate \ 
  && pip install -e .[test]

FROM base AS joinmarket