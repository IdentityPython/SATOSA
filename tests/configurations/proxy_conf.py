#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST

from example.test_module import TestModule

BASE = 'https://example.com'


def full_path(path):
    return os.path.join(os.path.dirname(__file__), path)


ATTRIBUTE_MODULE = TestModule(full_path("../users.json"),
                              "eduPersonPrincipalName")

CONFIG = {
    "entityid": "{}/proxy.xml".format(BASE),
    "service": {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/sso/redirect" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/sso/post" % BASE, BINDING_HTTP_POST),
                ],
            },
        },
        "sp": {
            "endpoints": {
                "assertion_consumer_service": [
                    ("%s/acs/post" % BASE, BINDING_HTTP_POST),
                    ("%s/acs/redirect" % BASE, BINDING_HTTP_REDIRECT)
                ],
            }
        },
    },
    "key_file": full_path("../pki/key.pem"),
    "cert_file": full_path("../pki/cert.pem"),
    "metadata": {
        "local": [full_path("unittest_idp.xml"),
                  full_path("unittest_sp.xml")],
    },
}
