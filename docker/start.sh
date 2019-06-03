#!/usr/bin/env bash

# for Click library to work in satosa-saml-metadata
export LC_ALL=C.UTF-8
export LANG=C.UTF-8

# exit immediately on failure
set -e

if [ -z "${DATA_DIR}" ]; then
   DATA_DIR=/opt/satosa/etc
fi

if [ ! -d "${DATA_DIR}" ]; then
   mkdir -p "${DATA_DIR}"
fi

if [ -z "${PROXY_PORT}" ]; then
   PROXY_PORT="8000"
fi

if [ -z "${METADATA_DIR}" ]; then
   METADATA_DIR="${DATA_DIR}"
fi

cd ${DATA_DIR}

mkdir -p ${METADATA_DIR}

if [ ! -d ${DATA_DIR}/attributemaps ]; then
   cp -pr /opt/satosa/attributemaps ${DATA_DIR}/attributemaps
fi

# Activate virtualenv
. /opt/satosa/bin/activate

# generate metadata for front- (IdP) and back-end (SP) and write it to mounted volume

satosa-saml-metadata proxy_conf.yaml ${DATA_DIR}/metadata.key ${DATA_DIR}/metadata.crt --dir ${METADATA_DIR}

# start the proxy
if [[ -f $GUNICORN_CONF ]]; then
    conf_opt="--config $GUNICORN_CONF"
fi
if [[ -f https.key && -f https.crt ]]; then # if HTTPS cert is available, use it
    exec gunicorn $conf_opt -b0.0.0.0:${PROXY_PORT} --keyfile https.key --certfile https.crt satosa.wsgi:app
else
    exec gunicorn $conf_opt -b0.0.0.0:${PROXY_PORT} satosa.wsgi:app
fi
