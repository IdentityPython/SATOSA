FROM ubuntu:16.04

RUN apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get install -y --no-install-recommends \
    git \
    python3-dev \
    build-essential \
    python3-pip \
    libffi-dev \
    libssl-dev \
    xmlsec1 \
    libyaml-dev && \
    apt-get clean

RUN mkdir -p /src/satosa
COPY . /src/satosa
COPY docker/setup.sh /setup.sh
COPY docker/start.sh /start.sh
RUN chmod +x /setup.sh /start.sh \
 && sync \
 && /setup.sh

COPY docker/attributemaps /opt/satosa/attributemaps

VOLUME /opt/satosa/etc
CMD ["/start.sh"]
ARG PROXY_PORT=8000
EXPOSE $PROXY_PORT
