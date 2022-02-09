FROM debian:buster-slim

RUN mkdir -p /jm/clientserver
WORKDIR /jm/clientserver

COPY . .

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates=* curl=* \
  python3-pip=* \
  && pip3 install 'wheel>=0.35.1' \
  && ./install.sh --docker-install \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
