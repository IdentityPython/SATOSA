import os
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from satosa.frontends.saml2 import SamlFrontend
from satosa.plugin_base.endpoint import FrontendModule

__author__ = 'mathiashedstrom'


def full_path(local_file):
    basedir = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(basedir, local_file)


XMLSEC_PATH = '/usr/local/bin/xmlsec1'

MODULE = SamlFrontend
RECEIVER = "Saml2IDP"
ENDPOINTS = {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                        BINDING_HTTP_POST: "sso/post"}}


class Saml2Frontend(FrontendModule):

    @staticmethod
    def get_instance(base_url):
        idpConfig = {
            "entityid": "{}/proxy.xml".format(base_url),
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
                  "base": base_url}

        return Saml2Frontend(MODULE, RECEIVER, config)
