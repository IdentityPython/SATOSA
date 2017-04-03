FROM ubuntu:16.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    python3-dev \
    build-essential \
    python3-pip \
    libffi-dev \
    libssl-dev \
    xmlsec1 \
    libyaml-dev

RUN mkdir -p /src/satosa
COPY . /src/satosa
COPY docker/setup.sh /setup.sh
RUN /setup.sh

COPY docker/start.sh /start.sh
COPY docker/attributemaps /opt/satosa/attributemaps

VOLUME /opt/satosa/etc
ENTRYPOINT ["/start.sh"]
