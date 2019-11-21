#!/bin/sh

set -e

VENV_DIR=/opt/satosa

python3 -m venv "$VENV_DIR"

"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -e /src/satosa/
