FROM debian:bookworm-slim

RUN mkdir -p /jm/clientserver
WORKDIR /jm/clientserver

COPY . .

RUN apt-get update && apt-get install -y --no-install-recommends gnupg ca-certificates=* curl=* \
  python3-pip=* python3=* \
  && pip3 config set global.break-system-packages true \
  && ./install.sh --docker-install \
  && apt-get purge -y --autoremove \
    python3-dev python3-pip \
    automake build-essential cpp pkg-config libffi-dev libssl-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

