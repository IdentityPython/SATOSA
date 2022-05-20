FROM python:3-slim-buster

ARG TARGETPLATFORM

RUN apt-get -y update && apt-get -y --no-install-recommends install xmlsec1 && apt-get -y upgrade
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then apt-get install -y --no-install-recommends gcc libc6-dev; fi

RUN mkdir -p /src/satosa
COPY . /src/satosa
COPY docker/setup.sh /setup.sh
COPY docker/start.sh /start.sh
RUN chmod +x /setup.sh /start.sh \
    && sync \
    && /setup.sh


RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then apt-get remove -y --no-install-recommends gcc libc6-dev; fi
RUN apt-get -y autoremove && apt-get -y clean

COPY docker/attributemaps /opt/satosa/attributemaps

VOLUME /opt/satosa/etc
CMD ["/start.sh"]
ARG PROXY_PORT=8000
EXPOSE $PROXY_PORT
