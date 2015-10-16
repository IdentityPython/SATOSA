#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os.path
from satosa.backends.oauth import FacebookBackend

from satosa.backends.openid_connect import OpenIdBackend
from satosa.plugin_base.endpoint import BackendModulePlugin

XMLSEC_PATH = '/usr/local/bin/xmlsec1'


def full_path(local_file):
    basedir = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(basedir, local_file)


PROVIDER = "facebook"
MODULE = FacebookBackend


class FacebookPlugin(BackendModulePlugin):

    def __init__(self, base_url):
        module_base = "%s/%s/" % (base_url, PROVIDER)
        config = {
            "base_url": module_base,
            "authz_page": "facebook",
            "client_config": {"client_id": "414989058592359"},
            "server_info": {
                "authorization_endpoint": "https://www.facebook.com/dialog/oauth",
                "token_endpoint": "https://graph.facebook.com/v2.5/oauth/access_token"
            },
            "response_type": "code",
            "client_secret": "a0c1bc1ba7e71cb2871b6349c55e867e",
            "state_cookie_name": "facebook_backend",
            "encryption_key": "#435ghfgh56tsdfsdg4356345wfgsdgvxzclkvj2l43k5j234534tfsdgvdfgjjn",
            "state_key": "facebook_1234234"
        }
        super(FacebookPlugin, self).__init__(MODULE, PROVIDER, config)
