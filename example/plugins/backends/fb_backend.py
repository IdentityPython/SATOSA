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
        module_base = base_url
        config = {
            "base_url": module_base,
            "authz_page": PROVIDER,
            "client_config": {"client_id": "414989058592359"},
            "server_info": {
                "authorization_endpoint": "https://www.facebook.com/dialog/oauth",
                "token_endpoint": "https://graph.facebook.com/v2.5/oauth/access_token"
            },
            #"response_type": "code",
            "client_secret": "a0c1bc1ba7e71cb2871b6349c55e867e",
            #"state_cookie_name": "facebook_backend",
            "encryption_key": "#435ghfgh56tsdfsdg4356345wfgsdgvxzclkvj2l43k5j234534tfsdgvdfgjjn",
            #"state_key": "facebook_1234234",
            "state_encryption_key": "dsfdsfsdafsadfsadfdsfdsfsdfsdafsdfsdafsdafasdfdsafsdfsdafdsa",
            #"verify_accesstoken_state": False
            "fields": ["id", "name", "first_name", "last_name", "middle_name", "picture",
                       "email", "verified", "gender", "timezone", "locale", "updated_time"],
            "oauth_to_internal": {'gender': 'male',
                                  'timezone': "osipreferredtimezone",
                                  'picture': "jpegphoto",
                                  'first_name': 'givenname',
                                  'email': 'email',
                                  'id': 'edupersontargetedid',
                                  'last_name': 'surname',
                                  'updated_time': 'osiicardtimelastupdated',
                                  'verified': 'osiotheremail',
                                  'name': 'name',
                                  'locale': 'preferredlanguage'}
        }
        super(FacebookPlugin, self).__init__(MODULE, PROVIDER, config)
