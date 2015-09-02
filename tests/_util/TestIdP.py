from __future__ import absolute_import
from future import standard_library

standard_library.install_aliases()
from builtins import object
import urllib.request, urllib.parse, urllib.error
from saml2.config import Config
from saml2.request import AuthnRequest
from saml2.sigver import encrypt_cert_from_item
from .TestHelper import get_post_action_body
from saml2.authn_context import AuthnBroker, authn_context_class_ref
from saml2.authn_context import PASSWORD

__author__ = 'haho0032'
from saml2 import server, BINDING_HTTP_POST


class Cache(object):
    def __init__(self):
        self.user2uid = {}
        self.uid2user = {}


def username_password_authn_dummy():
    return None


class TestIdP(object):
    USERS = {
        "testuser1": {
            "c": "SE",
            "displayName": "Hans Hoerberg",
            "eduPersonPrincipalName": "haho@example.com",
            "eduPersonScopedAffiliation": "staff@example.com",
            "eduPersonTargetedID": "one!for!all",
            "email": "hans@example.com",
            "givenName": "Hans",
            "initials": "P",
            "labeledURL": "http://www.example.com/haho My homepage",
            "norEduPersonNIN": "SE199012315555",
            "o": "Example Co.",
            "ou": "IT",
            "schacHomeOrganization": "example.com",
            "sn": "Hoerberg",
            "uid": "haho",
            "PVP-VERSION": "2.1",
            "PVP-PRINCIPALNAME": "Hoerberg",
            "PVP-PARTICIPANT-ID": "AT:TEST:1",
            "PVP-ROLES": "admin",
        },
        "testuser2": {
            "sn": "Testsson",
            "givenName": "Test",
            "eduPersonAffiliation": "student",
            "eduPersonScopedAffiliation": "student@example.com",
            "eduPersonPrincipalName": "test@example.com",
            "uid": "testuser1",
            "eduPersonTargetedID": "one!for!all",
            "c": "SE",
            "o": "Example Co.",
            "ou": "IT",
            "initials": "P",
            "schacHomeOrganization": "example.com",
            "email": "hans@example.com",
            "displayName": "Test Testsson",
            "labeledURL": "http://www.example.com/haho My homepage",
            "norEduPersonNIN": "SE199012315555"
        },
        "testuser3": {
            "sn": "Testsson",
            "givenName": "Test",
            "eduPersonAffiliation": "student",
            "eduPersonScopedAffiliation": "student@example.com",
            "eduPersonPrincipalName": "test@example.com",
            "uid": "testuser1",
            "eduPersonTargetedID": "one!for!all",
            "c": "SE",
            "o": "Example Co.",
            "ou": "IT",
            "initials": "P",
            "schacHomeOrganization": "example.com",
            "email": "hans@example.com",
            "displayName": "Test Testsson",
            "labeledURL": "http://www.example.com/haho My homepage",
            "norEduPersonNIN": "SE199012315555",
            "PVP-VERSION": "PVP-VERSION",
            "PVP-PRINCIPAL-NAME": "PVP-PRINCIPAL-NAME",
            "PVP-GIVENNAME": "PVP-GIVENNAME",
            "PVP-BIRTHDATE": "PVP-BIRTHDATE",
            "PVP-USERID": "PVP-USERID",
            "PVP-GID": "PVP-GID",
            "PVP-BPK": "PVP-BPK",
            "PVP-MAIL": "PVP-MAIL",
            "PVP-TEL": "PVP-TEL",
            "PVP-PARTICIPANT-ID": "PVP-PARTICIPANT-ID",
            "PVP-PARTICIPANT-OKZ": "PVP-PARTICIPANT-OKZ",
            "PVP-OU-OKZ": "PVP-OU-OKZ",
            "PVP-OU": "PVP-OU",
            "PVP-OU-GV-OU-ID": "PVP-OU-GV-OU-ID",
            "PVP-FUNCTION": "PVP-FUNCTION",
            "PVP-ROLES": "PVP-ROLES",
            "PVP-INVOICE-RECPT-ID": "PVP-INVOICE-RECPT-ID",
            "PVP-COST-CENTER-ID": "PVP-COST-CENTER-ID",
            "PVP-CHARGE-CODE": "PVP-CHARGE-CODE",
        },
    }

    def __init__(self, base_dir, conf_name=None, config=None):
        if config is not None:
            _conf = Config().load(config, metadata_construction=True)
            self.idp = server.Server(config=_conf, cache=Cache())
        else:
            if conf_name is None:
                conf_name = base_dir + "/external/at_egov_pvp2_config_test_idp"
            self.idp = server.Server(conf_name, cache=Cache())
        self.idp.ticket = {}
        self.authn_req = None
        self.binding_out = None
        self.destination = None

    def verify_pefim_authn_request_sp_cert_enc(self, saml_request, binding):
        try:
            xml = self.idp.unravel(saml_request, binding, AuthnRequest.msgtype)
            if xml.lower().find("begin certificate") > 0 or xml.lower().find("end certificate") > 0:
                return False
            xml_1 = xml.split("Extensions", 1)
            xml_2 = xml_1[1].split("SPCertEnc", 1)
            xml_3 = xml_2[1].split("KeyInfo", 1)
            xml_4 = xml_3[1].split("X509Data", 1)
            xml_5 = xml_4[1].split("X509Certificate", 1)
            return len(xml_5) == 2
        except Exception:
            return False

    # binding = BINDING_HTTP_REDIRECT or BINDING_HTTP_POST
    def handle_authn_request(self, saml_request, relay_state, binding, userid):

        self.authn_req = self.idp.parse_authn_request(saml_request, binding)
        _encrypt_cert = encrypt_cert_from_item(self.authn_req.message)

        self.binding_out, self.destination = self.idp.pick_binding(
            "assertion_consumer_service",
            bindings=None,
            entity_id=self.authn_req.message.issuer.text,
            request=self.authn_req.message)
        resp_args = self.idp.response_args(self.authn_req.message)
        authn_broker = AuthnBroker()
        authn_broker.add(authn_context_class_ref(PASSWORD),
                         username_password_authn_dummy,
                         10,
                         "http://test.idp.se")
        authn_broker.get_authn_by_accr(PASSWORD)
        resp_args["authn"] = authn_broker.get_authn_by_accr(PASSWORD)
        _resp = self.idp.create_authn_response(TestIdP.USERS[userid],
                                               userid=userid,
                                               encrypt_cert=_encrypt_cert,
                                               encrypt_assertion_self_contained=True,
                                               encrypted_advice_attributes=True,
                                               **resp_args)
        kwargs = {}
        http_args = self.idp.apply_binding(BINDING_HTTP_POST,
                                           "%s" % _resp,
                                           self.destination,
                                           relay_state,
                                           response=True,
                                           **kwargs)
        action, body = get_post_action_body(http_args["data"][3])
        return action, urllib.parse.urlencode(body)

    def simple_verify_authn_response_ava(self, ava, userid):
        TestIdP.USERS[userid]
        if ava is None or len(ava) == 0:
            return False
        return True
