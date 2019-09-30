#!/usr/bin/env sh

set -e

# for Click library to work in satosa-saml-metadata
export LC_ALL="C.UTF-8"
export LANG="C.UTF-8"

if [ -z "${DATA_DIR}" ]
then DATA_DIR=/opt/satosa/etc
fi

if [ ! -d "${DATA_DIR}" ]
then mkdir -p "${DATA_DIR}"
fi

if [ -z "${PROXY_PORT}" ]
then PROXY_PORT="8000"
fi

if [ -z "${METADATA_DIR}" ]
then METADATA_DIR="${DATA_DIR}"
fi

if [ ! -d "${DATA_DIR}/attributemaps" ]
then cp -pr /opt/satosa/attributemaps "${DATA_DIR}/attributemaps"
fi

# activate virtualenv
. /opt/satosa/bin/activate

# generate metadata for frontend(IdP interface) and backend(SP interface)
# write the result to mounted volume
mkdir -p "${METADATA_DIR}"
satosa-saml-metadata              \
	"${DATA_DIR}/proxy_conf.yaml" \
	"${DATA_DIR}/metadata.key"    \
	"${DATA_DIR}/metadata.crt"    \
	--dir "${METADATA_DIR}"

# if the user provided a gunicorn configuration, use it
if [ -f "$GUNICORN_CONF" ]
then conf_opt="--config ${GUNICORN_CONF}"
else conf_opt="--chdir ${DATA_DIR}"
fi

# if HTTPS cert is available, use it
https_key="${DATA_DIR}/https.key"
https_crt="${DATA_DIR}/https.crt"
if [ -f "$https_key" -a -f "$https_crt" ]
then https_opts="--keyfile ${https_key} --certfile ${https_crt}"
fi

# if a chain is available, use it
chain_pem="${DATA_DIR}/chain.pem"
if [ -f "$chain_pem" ]
then chain_opts="--ca-certs chain.pem"
fi

# start the proxy
exec gunicorn $conf_opt        \
	-b 0.0.0.0:"${PROXY_PORT}" \
	satosa.wsgi:app            \
	$https_opts                \
	$chain_opts                \
	;
