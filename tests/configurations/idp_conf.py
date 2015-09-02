#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST


def full_path(path):
    return os.path.join(os.path.dirname(__file__), path)


BASE = "http://example.com"

CONFIG = {
    "entityid": "{}/unittest_idp.xml".format(BASE),
    "service": {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/sso/post" % BASE, BINDING_HTTP_POST),
                    ("%s/sso/redirect" % BASE, BINDING_HTTP_REDIRECT),
                ],
            },
        },
    },
    "key_file": full_path("../pki/key.pem"),
    "cert_file": full_path("../pki/cert.pem"),
    "metadata": {
        "local": [full_path("proxy.xml")],
    }
}
