#!/bin/bash

pip3 install --upgrade virtualenv

virtualenv -p python3 /opt/satosa
/opt/satosa/bin/pip install --upgrade pip setuptools
/opt/satosa/bin/pip install /src/satosa/

