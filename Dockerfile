FROM debian:stable-slim

RUN apt-get update \
    && apt-get -y dist-upgrade \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        xmlsec1 \
    && apt-get clean

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
