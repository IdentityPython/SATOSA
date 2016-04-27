"""
Tests for the SAML frontend module src/frontends/saml2.py.
"""
import re
from collections import Counter
from urllib import parse
from urllib.parse import urlparse, parse_qs

import pytest
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.authn_context import PASSWORD
from saml2.config import SPConfig
from saml2.entity_category import refeds, swamid
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP
from saml2.entity_category.swamid import SFS_1993_1153, RESEARCH_AND_EDUCATION, EU
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT
from saml2.samlp import NameIDPolicy

from satosa.context import Context
from satosa.frontends.saml2 import SamlFrontend
from satosa.internal_data import InternalResponse, AuthenticationInformation, InternalRequest
from satosa.state import State
from satosa.util import saml_name_format_to_hash_type
from tests.users import USERS
from tests.util import FakeSP, create_metadata_from_config_dict

INTERNAL_ATTRIBUTES = {
    'attributes': {'displayname': {'openid': ['nickname'], 'saml': ['displayName']},
                   'givenname': {'saml': ['givenName'], 'openid': ['given_name'],
                                 'facebook': ['first_name']},
                   'mail': {'saml': ['email', 'emailAdress', 'mail'], 'openid': ['email'],
                            'facebook': ['email']},
                   'edupersontargetedid': {'saml': ['eduPersonTargetedID'], 'openid': ['sub'],
                                           'facebook': ['id']},
                   'name': {'saml': ['cn'], 'openid': ['name'], 'facebook': ['name']},
                   'surname': {'saml': ['sn', 'surname'], 'openid': ['family_name'],
                               'facebook': ['last_name']}}}

ENDPOINTS = {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                        BINDING_HTTP_POST: "sso/post"}}


class TestSamlFrontend:
    def construct_base_url_from_entity_id(self, entity_id):
        return "{parsed.scheme}://{parsed.netloc}".format(parsed=urlparse(entity_id))

    def setup_for_authn_req(self, idp_conf, sp_conf, nameid_format=None, relay_state="relay_state"):
        base = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        config = {"idp_config": idp_conf, "endpoints": ENDPOINTS, "base": base,
                  "state_id": "state_id"}
        sp_metadata_str = create_metadata_from_config_dict(sp_conf)
        idp_conf["metadata"]["inline"] = [sp_metadata_str]

        samlfrontend = SamlFrontend(lambda context, internal_req: (context, internal_req),
                                    INTERNAL_ATTRIBUTES, config)
        samlfrontend.register_endpoints(["saml"])

        idp_metadata_str = create_metadata_from_config_dict(samlfrontend.idp_config)
        sp_conf["metadata"]["inline"].append(idp_metadata_str)

        fakesp = FakeSP(None, config=SPConfig().load(sp_conf, metadata_construction=False))
        context = Context()
        context.state = State()
        context.request = parse.parse_qs(
            urlparse(fakesp.make_auth_req(samlfrontend.idp_config["entityid"], nameid_format, relay_state)).query)
        tmp_dict = {}
        for val in context.request:
            if isinstance(context.request[val], list):
                tmp_dict[val] = context.request[val][0]
            else:
                tmp_dict[val] = context.request[val]
        context.request = tmp_dict

        return context, samlfrontend

    @pytest.mark.parametrize("conf", [
        None,
        {"idp_config_notok": {}, "endpoints": {}, "base": "base",
         "state_id": "state_id"},
        {"idp_config": {}, "endpoints_notok": {}, "base": "base",
         "state_id": "state_id"},
        {"idp_config": {}, "endpoints": {}, "base_notok": "base",
         "state_id": "state_id"}
    ])
    def test_config_error_handling(self, conf):
        with pytest.raises(AssertionError):
            SamlFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES, conf)

    def test_register_endpoints(self, idp_conf):
        """
        Tests the method register_endpoints
        """

        def get_path_from_url(url):
            return urlparse(url).path.lstrip("/")

        metadata_url = "http://example.com/SAML2IDP/metadata"
        config = {"idp_config": idp_conf, "endpoints": ENDPOINTS,
                  "base": self.construct_base_url_from_entity_id(idp_conf["entityid"]),
                  "state_id": "state_id",
                  "publish_metadata": metadata_url}

        samlfrontend = SamlFrontend(lambda context, internal_req: (context, internal_req),
                                    INTERNAL_ATTRIBUTES, config)

        providers = ["foo", "bar"]
        url_map = samlfrontend.register_endpoints(providers)
        all_idp_endpoints = [get_path_from_url(v[0][0]) for v in idp_conf["service"]["idp"]["endpoints"].values()]
        compiled_regex = [re.compile(regex) for regex, _ in url_map]
        for endp in all_idp_endpoints:
            assert any(p.match(endp) for p in compiled_regex)

        assert any(p.match(get_path_from_url(metadata_url)) for p in compiled_regex)

    def test_handle_authn_request(self, idp_conf, sp_conf):
        """
        Performs a complete test for the module. The flow should be accepted.
        """
        context, samlfrontend = self.setup_for_authn_req(idp_conf, sp_conf)
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.requestor == sp_conf["entityid"]

        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml")
        internal_response = InternalResponse(auth_info=auth_info)
        internal_response.set_user_id_hash_type(internal_req.user_id_hash_type)
        internal_response.add_attributes(USERS["testuser1"])

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)

        fakesp = FakeSP(None, config=SPConfig().load(sp_conf, metadata_construction=False))
        resp = fakesp.parse_authn_request_response(resp_dict['SAMLResponse'][0],
                                                   BINDING_HTTP_REDIRECT)
        for key in resp.ava:
            assert USERS["testuser1"][key] == resp.ava[key]

    def test_handle_authn_request_without_name_id_policy(self, idp_conf, sp_conf):
        """
        Performs a complete test for the module. The flow should be accepted.
        """
        context, samlfrontend = self.setup_for_authn_req(idp_conf, sp_conf, nameid_format="")
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.requestor == sp_conf["entityid"]

        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml")
        internal_response = InternalResponse(auth_info=auth_info)
        internal_response.set_user_id_hash_type(internal_req.user_id_hash_type)
        internal_response.add_attributes(USERS["testuser1"])

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)

        fakesp = FakeSP(None, config=SPConfig().load(sp_conf, metadata_construction=False))
        resp = fakesp.parse_authn_request_response(resp_dict['SAMLResponse'][0],
                                                   BINDING_HTTP_REDIRECT)
        for key in resp.ava:
            assert USERS["testuser1"][key] == resp.ava[key]

    def test_handle_authn_response_without_relay_state(self, idp_conf, sp_conf):
        """
        Performs a complete test for the module. The flow should be accepted.
        """
        context, samlfrontend = self.setup_for_authn_req(idp_conf, sp_conf, relay_state=None)
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.requestor == sp_conf["entityid"]

        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml")
        internal_response = InternalResponse(auth_info=auth_info)
        internal_response.set_user_id_hash_type(internal_req.user_id_hash_type)
        internal_response.add_attributes(USERS["testuser1"])

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)

        fakesp = FakeSP(None, config=SPConfig().load(sp_conf, metadata_construction=False))
        resp = fakesp.parse_authn_request_response(resp_dict['SAMLResponse'][0],
                                                   BINDING_HTTP_REDIRECT)
        for key in resp.ava:
            assert USERS["testuser1"][key] == resp.ava[key]

    def test_get_filter_attributes_with_sp_requested_attributes_without_friendlyname(self,
                                                                                     idp_conf):
        sp_metadata_str = """<?xml version="1.0"?>
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://sp.example.com">
          <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol">
            <md:AttributeConsumingService>
              <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
              <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
              <md:RequestedAttribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
              <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true"/>
              <md:RequestedAttribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
              <md:RequestedAttribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
              <md:RequestedAttribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
            </md:AttributeConsumingService>
          </md:SPSSODescriptor>
        </md:EntityDescriptor>
        """

        idp_conf["metadata"] = {"inline": [sp_metadata_str]}

        base = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        conf = {"idp_config": idp_conf, "endpoints": ENDPOINTS, "base": base,
                "state_id": "state_id"}

        internal_attributes = {"attributes": {attr_name: {"saml": [attr_name]} for attr_name in
                                              ["edupersontargetedid", "edupersonprincipalname",
                                               "edupersonaffiliation", "mail", "displayname", "sn",
                                               "givenname"]}}  # no op mapping for saml attribute names

        samlfrontend = SamlFrontend(None, internal_attributes, conf)
        samlfrontend.register_endpoints(["testprovider"])

        internal_req = InternalRequest(saml_name_format_to_hash_type(NAMEID_FORMAT_PERSISTENT),
                                       "http://sp.example.com",
                                       "Example SP")
        filtered_attributes = samlfrontend.get_filter_attributes(samlfrontend.idp,
                                                                 samlfrontend.idp.config.getattr(
                                                                     "policy", "idp"),
                                                                 internal_req.requestor, None)

        assert set(filtered_attributes) == set(
            ["edupersontargetedid", "edupersonprincipalname", "edupersonaffiliation", "mail",
             "displayname", "sn", "givenname"])

    def test_acr_mapping_in_authn_response(self, idp_conf, sp_conf):
        eidas_loa_low = "http://eidas.europa.eu/LoA/low"
        loa = {"": eidas_loa_low}

        base = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        conf = {"idp_config": idp_conf, "endpoints": ENDPOINTS, "base": base,
                "state_id": "state_id", "acr_mapping": loa}

        samlfrontend = SamlFrontend(None, INTERNAL_ATTRIBUTES, conf)
        samlfrontend.register_endpoints(["foo"])

        idp_metadata_str = create_metadata_from_config_dict(samlfrontend.idp_config)
        sp_conf["metadata"]["inline"].append(idp_metadata_str)
        fakesp = FakeSP(None, config=SPConfig().load(sp_conf, metadata_construction=False))

        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml")
        internal_response = InternalResponse(auth_info=auth_info)
        context = Context()
        context.state = State()

        resp_args = {
            "name_id_policy": NameIDPolicy(format=NAMEID_FORMAT_TRANSIENT),
            "in_response_to": None,
            "destination": "",
            "sp_entity_id": None,
            "binding": BINDING_HTTP_REDIRECT

        }
        request_state = samlfrontend.save_state(context, resp_args, "")
        context.state.add(conf["state_id"], request_state)

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)
        resp = fakesp.parse_authn_request_response(resp_dict['SAMLResponse'][0],
                                                   BINDING_HTTP_REDIRECT)

        assert len(resp.assertion.authn_statement) == 1
        authn_context_class_ref = resp.assertion.authn_statement[
            0].authn_context.authn_context_class_ref
        assert authn_context_class_ref.text == eidas_loa_low

    def test_acr_mapping_per_idp_in_authn_response(self, idp_conf, sp_conf):
        expected_loa = "LoA1"
        loa = {"": "http://eidas.europa.eu/LoA/low", idp_conf["entityid"]: expected_loa}

        base = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        conf = {"idp_config": idp_conf, "endpoints": ENDPOINTS, "base": base,
                "state_id": "state_id", "acr_mapping": loa}

        samlfrontend = SamlFrontend(None, INTERNAL_ATTRIBUTES, conf)
        samlfrontend.register_endpoints(["foo"])

        idp_metadata_str = create_metadata_from_config_dict(samlfrontend.idp_config)
        sp_conf["metadata"]["inline"].append(idp_metadata_str)
        fakesp = FakeSP(None, config=SPConfig().load(sp_conf, metadata_construction=False))

        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", idp_conf["entityid"])
        internal_response = InternalResponse(auth_info=auth_info)
        context = Context()
        context.state = State()

        resp_args = {
            "name_id_policy": NameIDPolicy(format=NAMEID_FORMAT_TRANSIENT),
            "in_response_to": None,
            "destination": "",
            "sp_entity_id": None,
            "binding": BINDING_HTTP_REDIRECT

        }
        request_state = samlfrontend.save_state(context, resp_args, "")
        context.state.add(conf["state_id"], request_state)

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)
        resp = fakesp.parse_authn_request_response(resp_dict['SAMLResponse'][0],
                                                   BINDING_HTTP_REDIRECT)

        assert len(resp.assertion.authn_statement) == 1
        authn_context_class_ref = resp.assertion.authn_statement[
            0].authn_context.authn_context_class_ref
        assert authn_context_class_ref.text == expected_loa

    @pytest.mark.parametrize('entity_category, expected_attributes', [
        ([RESEARCH_AND_SCHOLARSHIP], refeds.RELEASE[RESEARCH_AND_SCHOLARSHIP]),
        ([SFS_1993_1153], swamid.RELEASE[SFS_1993_1153]),
        ([RESEARCH_AND_EDUCATION, EU], swamid.RELEASE[(RESEARCH_AND_EDUCATION, EU)])
    ])
    def test_respect_sp_entity_categories(self, entity_category, expected_attributes, idp_conf, sp_conf):
        base = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        conf = {"idp_config": idp_conf, "endpoints": ENDPOINTS, "base": base,
                "state_id": "state_id"}

        internal_attributes = {attr_name: {"saml": [attr_name.lower()]} for attr_name in expected_attributes}
        samlfrontend = SamlFrontend(None, dict(attributes=internal_attributes), conf)
        samlfrontend.register_endpoints(["foo"])

        idp_metadata_str = create_metadata_from_config_dict(samlfrontend.idp_config)
        sp_conf["metadata"]["inline"].append(idp_metadata_str)
        sp_conf["entity_category"] = entity_category
        fakesp = FakeSP(None, config=SPConfig().load(sp_conf, metadata_construction=False))

        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", idp_conf["entityid"])
        internal_response = InternalResponse(auth_info=auth_info)

        user_attributes = {k: "foo" for k in expected_attributes}
        user_attributes.update({k: "bar" for k in ["extra", "more", "stuff"]})
        internal_response.add_attributes(user_attributes)
        context = Context()
        context.state = State()

        resp_args = {
            "name_id_policy": NameIDPolicy(format=NAMEID_FORMAT_TRANSIENT),
            "in_response_to": None,
            "destination": "",
            "sp_entity_id": None,
            "binding": BINDING_HTTP_REDIRECT
        }
        request_state = samlfrontend.save_state(context, resp_args, "")
        context.state.add(conf["state_id"], request_state)

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)
        resp = fakesp.parse_authn_request_response(resp_dict['SAMLResponse'][0],
                                                   BINDING_HTTP_REDIRECT)

        assert Counter(resp.ava.keys()) == Counter(expected_attributes)