#!/usr/bin/env python
# pylint: disable = missing-docstring
# -*- coding: utf-8 -*-
import os.path

# try:
#     from saml2.sigver import get_xmlsec_binary
# except ImportError:
#     get_xmlsec_binary = None
xmlsec_path = '/usr/local/bin/xmlsec1'


def full_path(local_file):
    basedir = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(basedir, local_file)


HOST = 'localhost'
PORT = 8090

BASE = 'https://%s:%s' % (HOST, PORT)

PLUGIN_PATH = [full_path(".")]
BACKEND_MODULES = ["saml2_module_conf"]
FRONTEND_MODULES = ["saml2_frontend_plugin"]
