#!/bin/bash

pip3 install --upgrade virtualenv

virtualenv -p python3 /opt/venv
/opt/venv/bin/pip install --upgrade pip setuptools
/opt/venv/bin/pip install /src/satosa/

