#!/usr/bin/env python
# -*- coding: utf-8 -*-
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
import os.path
from satosa.backends.saml2 import SamlSP

# try:
#     from saml2.sigver import get_xmlsec_binary
# except ImportError:
#     get_xmlsec_binary = None
from satosa.plugin_base.backend import BackendPlugin

xmlsec_path = '/usr/local/bin/xmlsec1'


def full_path(local_file):
    basedir = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(basedir, local_file)


PROVIDER = "Saml2"
MODULE = SamlSP


class Saml2Plugin(BackendPlugin):
    def __init__(self, config):
        super(Saml2Plugin, self).__init__(SamlSP, PROVIDER, config)


def setup(base):
    MODULE_BASE = "%s/%s" % (base, PROVIDER)
    config = {
        "idp_entity_id": "https://example.com/unittest_idp.xml",
        "entityid": "%s/proxy_sp.xml" % MODULE_BASE,
        "service": {
            "sp": {
                "allow_unsolicited": True,
                "endpoints": {
                    "assertion_consumer_service": [
                        ("%s/acs/post" % MODULE_BASE, BINDING_HTTP_POST),
                        ("%s/acs/redirect" % MODULE_BASE, BINDING_HTTP_REDIRECT)
                    ],
                }
            }
        },
        "key_file": full_path("../pki/key.pem"),
        "cert_file": full_path("../pki/cert.pem"),
        "metadata": {
            "local": [full_path("unittest_idp.xml")],
        },

        "xmlsec_binary": xmlsec_path,
    }

    return Saml2Plugin(config)
