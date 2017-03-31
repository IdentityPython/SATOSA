#!/bin/bash

pip3 install --upgrade pip setuptools virtualenv

virtualenv -p python3 /opt/satosa
/opt/satosa/bin/pip install SATOSA

