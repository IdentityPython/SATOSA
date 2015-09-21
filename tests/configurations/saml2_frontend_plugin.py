import os
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from satosa.plugin_base.frontend import FrontendPlugin
from satosa.frontends.saml2 import SamlFrontend

__author__ = 'mathiashedstrom'


def full_path(local_file):
    basedir = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(basedir, local_file)


XMLSEC_PATH = '/usr/local/bin/xmlsec1'

MODULE = SamlFrontend
RECEIVER = "Saml2IDP"
ENDPOINTS = {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                        BINDING_HTTP_POST: "sso/post"}}


def setup(base):
    idpConfig = {
        "entityid": "{}/proxy.xml".format(base),
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
        "xmlsec_binary": XMLSEC_PATH,
    }

    config = {"idp_config": idpConfig,
              "endpoints": ENDPOINTS,
              "base": base}

    return FrontendPlugin(MODULE, RECEIVER, config)
