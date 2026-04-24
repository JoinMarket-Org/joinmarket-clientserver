FROM debian:bookworm-slim

RUN mkdir -p /jm/clientserver
WORKDIR /jm/clientserver

COPY . .

ARG WITH_MATPLOTLIB='0'
RUN apt-get update && apt-get install -y --no-install-recommends gnupg ca-certificates=* curl=* \
  python3-packaging=* python3-pip=* python3=* \
  && pip3 config set global.break-system-packages true \
  && pip3 install 'wheel>=0.35.1' \
  && ./install.sh --docker-install \
  && apt-get purge -y --autoremove python3-pip \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

