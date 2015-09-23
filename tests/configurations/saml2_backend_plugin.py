#!/usr/bin/env python
# -*- coding: utf-8 -*-
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
import os.path
from satosa.backends.saml2 import SamlBackend
from satosa.plugin_base.endpoint import BackendModule

# try:
#     from saml2.sigver import get_xmlsec_binary
# except ImportError:
#     get_xmlsec_binary = None
xmlsec_path = '/usr/local/bin/xmlsec1'


def full_path(local_file):
    basedir = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(basedir, local_file)


PROVIDER = "Saml2"
MODULE = SamlBackend


class Saml2Module(BackendModule):
    @staticmethod
    def get_instance(base_url):
        module_base = "%s/%s" % (base_url, PROVIDER)
        config = {
            "idp_entity_id": "https://example.com/unittest_idp.xml",
            "entityid": "%s/proxy_sp.xml" % module_base,
            "service": {
                "sp": {
                    "allow_unsolicited": True,
                    "endpoints": {
                        "assertion_consumer_service": [
                            ("%s/acs/post" % module_base, BINDING_HTTP_POST),
                            ("%s/acs/redirect" % module_base, BINDING_HTTP_REDIRECT)
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

        return Saml2Module(SamlBackend, PROVIDER, config)
