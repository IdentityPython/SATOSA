#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os.path

from satosa.backends.openid_connect import OpenIdBackend
from satosa.plugin_base.endpoint import BackendModulePlugin

XMLSEC_PATH = '/usr/local/bin/xmlsec1'


def full_path(local_file):
    basedir = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(basedir, local_file)


PROVIDER = "openid_connect"
MODULE = OpenIdBackend


class OpenidPlugin(BackendModulePlugin):
    def __init__(self, base_url):
        module_base = "%s/%s/" % (base_url, PROVIDER)
        config = RpConfig(module_base)
        super(OpenidPlugin, self).__init__(OpenIdBackend, PROVIDER, config)


class RpConfig(object):
    def __init__(self, module_base):
        self.CLIENTS = {
            "": {
                "client_info": {
                    "application_type": "web",
                    "application_name": "SATOSA",
                    "contacts": ["ops@example.com"],
                    "redirect_uris": ["%sauthz_cb" % module_base],
                    "post_logout_redirect_uris": ["%slogout" % module_base],
                    "response_types": ["code"],
                    "subject_type": "pairwise"
                },
                "behaviour": {
                    "response_type": "code",
                    "scope": ["openid", "profile", "email", "address", "phone"],
                }
            },
        }
        self.ACR_VALUES = ["PASSWORD"]
        self.VERIFY_SSL = False
        self.OP_URL = "https://localhost:8092"
        self.STATE_ENCRYPTION_KEY = "Qrn9IQ5hr9uUnIdNQe2e0KxsmR3CusyARs3RKLjp"
        self.STATE_ID = "OpenID_Qrn9R3Cus"
