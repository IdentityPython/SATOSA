#!/usr/bin/env python
# pylint: disable = missing-docstring
# -*- coding: utf-8 -*-
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
import os.path
from vopaas_proxy.util.attribute_module import IdentityAttributes

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

# Discovery to server if proxy is used with multiple IdP's
DISCO_SRV = "http://localhost/role/idp.ds"

ATTRIBUTE_MODULE = IdentityAttributes()

PLUGIN_PATH = [full_path(".")]
BACKEND_MODULES = ["saml2_module_conf"]

ENDPOINTS = {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                        BINDING_HTTP_POST: "sso/post"}}

CONFIG = {
    "backends": {},
    "entityid": "{}/proxy.xml".format(BASE),
    "service": {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [],
            },
        },
    },
    "key_file": full_path("../pki/key.pem"),
    "cert_file": full_path("../pki/cert.pem"),
    "metadata": {
        "local": [full_path("unittest_sp.xml")],
    },
    "xmlsec_binary": xmlsec_path,
}
