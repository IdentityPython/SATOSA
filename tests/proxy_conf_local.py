#!/usr/bin/env python
# pylint: disable = missing-docstring
# -*- coding: utf-8 -*-
from __future__ import absolute_import
import os.path

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.entity_category.at_egov_pvp2 import PVP2, PVP2CHARGE
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from . import proxy_server_conf_default

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    XMLSEC_PATH = get_xmlsec_binary(["/opt/local/bin"])
else:
    XMLSEC_PATH = '/usr/bin/xmlsec1'

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


BASE = proxy_server_conf_default.ISSUER + ":%s" % proxy_server_conf_default.PORT

DISCO_SRV = "https://md.nordu.net/role/idp.ds"

SP_ENTITY_CATEGORIES = [{"name": "pvp2", "entcat": [PVP2]},
                        {"name": "pvp2charge", "entcat": [PVP2CHARGE]}]

# None if no default SP should be used, otherwise a list. The list may be empty.
SP_ENTITY_CATEGORIES_DEFAULT = []

CONFIG = {
    "entityid": "%sproxy.xml" % BASE,
    "description": "A SAML2SAML PEFIM proxy",
    "valid_for": 168,
    "service": {
        "idp": {
            "name": "PEFIM IdP",
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/sso/redirect" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/sso/post" % BASE, BINDING_HTTP_POST),
                ],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 15},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                    "entity_categories": ["at_egov_pvp2"],
                    "fail_on_missing_requested": False
                },
            },
            "subject_data": ("dict", None),  # "./idp.subject",
            "name_id_format": NAMEID_FORMAT_PERSISTENT,
            "want_authn_requests_signed": False
        },
        "sp": {
            "authn_requests_signed": "true",
            "want_response_signed": "true",
            # "required_attributes": ["sn", "givenname", "uid",
            #                        "edupersonaffiliation"],
            # "optional_attributes": ["title"],
            "endpoints": {
                "assertion_consumer_service": [
                    ("%s/acs/post" % BASE, BINDING_HTTP_POST),
                    ("%s/acs/redirect" % BASE, BINDING_HTTP_REDIRECT)
                ],
                "discovery_response": [
                    ("%s/disco" % BASE, BINDING_DISCO)
                ]
            },
            "name_id_format": NAMEID_FORMAT_PERSISTENT,
        },
    },
    "debug": 1,
    "key_file": full_path("proxy_cert/new_server.key"),
    "cert_file": full_path("proxy_cert/new_server.crt"),
    "metadata": {
        # "mdfile": ["swamid2.md"],
        "local": [
            BASEDIR + "/external/pvp2_config_transient_test_sp.xml",
            BASEDIR + "/external/pvp2_config_test_sp.xml",
            BASEDIR + "/external/at_egov_pvp2_config_test_idp.xml",
            BASEDIR + "/external/swamid_config_test_idp.xml",
            BASEDIR + "/external/pvp2charge_config_test_sp.xml"
        ]
    },
    "organization": {
        "display_name": "Test Testsson",
        "name": "Test Testsson",
        "url": "http://www.example.com",
    },
    "contact_person": [
        {
            "contact_type": "technical",
            "given_name": "Test",
            "sur_name": "Technical",
            "email_address": "test.technical@example.com"
        }, {
            "contact_type": "support",
            "given_name": "Support",
            "email_address": "support@example.com"
        },
    ],
    # This database holds the map between a subjects local identifier and
    # the identifier returned to a SP
    "xmlsec_binary": XMLSEC_PATH,
    "logger": {
        "rotating": {
            "filename": "pefim_proxy_idp.log",
            "maxBytes": 500000,
            "backupCount": 5,
        },
        "loglevel": "debug",
    }
}
