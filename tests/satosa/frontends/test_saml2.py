"""
Tests for the SAML frontend module src/frontends/saml2.py.
"""
import itertools
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

import pytest
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.authn_context import PASSWORD
from saml2.config import SPConfig
from saml2.entity_category import refeds, swamid, edugain
from saml2.entity_category.edugain import COCO
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP
from saml2.entity_category.swamid import SFS_1993_1153, RESEARCH_AND_EDUCATION, EU, HEI, NREN
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT, \
    NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_UNSPECIFIED
from saml2.samlp import NameIDPolicy

from satosa.attribute_mapping import AttributeMapper
from satosa.frontends.saml2 import SAMLFrontend, saml_name_id_format_to_hash_type, \
    hash_type_to_saml_name_id_format, SAMLMirrorFrontend
from satosa.internal_data import InternalResponse, AuthenticationInformation, InternalRequest
from satosa.internal_data import UserIdHashType
from satosa.state import State
from satosa.exception import SATOSAModuleError
from tests.users import USERS
from tests.util import FakeSP, create_metadata_from_config_dict

INTERNAL_ATTRIBUTES = {
    "attributes": {
        "displayname": {"saml": ["displayName"]},
        "givenname": {"saml": ["givenName"]},
        "mail": {"saml": ["email", "emailAdress", "mail"]},
        "edupersontargetedid": {"saml": ["eduPersonTargetedID"]},
        "name": {"saml": ["cn"]},
        "surname": {"saml": ["sn", "surname"]}
    }
}

ENDPOINTS = {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                        BINDING_HTTP_POST: "sso/post"}}
BASE_URL = "https://satosa-idp.example.com"


class TestSAMLFrontend:
    @pytest.fixture
    def internal_response(self, idp_conf):
        auth_info = AuthenticationInformation(PASSWORD, "2015-09-30T12:21:37Z", idp_conf["entityid"])
        internal_response = InternalResponse(auth_info=auth_info)
        internal_response.attributes = AttributeMapper(INTERNAL_ATTRIBUTES).to_internal("saml", USERS["testuser1"])
        return internal_response

    def construct_base_url_from_entity_id(self, entity_id):
        return "{parsed.scheme}://{parsed.netloc}".format(parsed=urlparse(entity_id))

    def setup_for_authn_req(self, context, idp_conf, sp_conf, nameid_format=None, relay_state="relay_state",
                            internal_attributes=INTERNAL_ATTRIBUTES, extra_config={}):
        config = {"idp_config": idp_conf, "endpoints": ENDPOINTS}
        config.update(extra_config)
        sp_metadata_str = create_metadata_from_config_dict(sp_conf)
        idp_conf["metadata"]["inline"] = [sp_metadata_str]

        base_url = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        samlfrontend = SAMLFrontend(lambda ctx, internal_req: (ctx, internal_req),
                                    internal_attributes, config, base_url, "saml_frontend")
        samlfrontend.register_endpoints(["saml"])

        idp_metadata_str = create_metadata_from_config_dict(samlfrontend.idp_config)
        sp_conf["metadata"]["inline"].append(idp_metadata_str)

        fakesp = FakeSP(SPConfig().load(sp_conf, metadata_construction=False))
        destination, auth_req = fakesp.make_auth_req(samlfrontend.idp_config["entityid"], nameid_format, relay_state)
        context.request = auth_req
        tmp_dict = {}
        for val in context.request:
            if isinstance(context.request[val], list):
                tmp_dict[val] = context.request[val][0]
            else:
                tmp_dict[val] = context.request[val]
        context.request = tmp_dict

        return samlfrontend

    def get_auth_response(self, samlfrontend, context, internal_response, sp_conf, idp_metadata_str):
        sp_config = SPConfig().load(sp_conf, metadata_construction=False)
        resp_args = {
            "name_id_policy": NameIDPolicy(format=NAMEID_FORMAT_TRANSIENT),
            "in_response_to": None,
            "destination": sp_config.endpoint("assertion_consumer_service", binding=BINDING_HTTP_REDIRECT)[0],
            "sp_entity_id": sp_conf["entityid"],
            "binding": BINDING_HTTP_REDIRECT
        }
        request_state = samlfrontend._create_state_data(context, resp_args, "")
        context.state[samlfrontend.name] = request_state

        resp = samlfrontend.handle_authn_response(context, internal_response)

        sp_conf["metadata"]["inline"].append(idp_metadata_str)
        fakesp = FakeSP(sp_config)
        resp_dict = parse_qs(urlparse(resp.message).query)
        return fakesp.parse_authn_request_response(resp_dict["SAMLResponse"][0], BINDING_HTTP_REDIRECT)

    @pytest.mark.parametrize("conf", [
        None,
        {"idp_config_notok": {}, "endpoints": {}},
        {"idp_config": {}, "endpoints_notok": {}}
    ])
    def test_config_error_handling(self, conf):
        with pytest.raises(ValueError):
            SAMLFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES, conf, "base_url", "saml_frontend")

    def test_register_endpoints(self, idp_conf):
        """
        Tests the method register_endpoints
        """

        def get_path_from_url(url):
            return urlparse(url).path.lstrip("/")

        config = {"idp_config": idp_conf, "endpoints": ENDPOINTS}

        base_url = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        samlfrontend = SAMLFrontend(lambda context, internal_req: (context, internal_req),
                                    INTERNAL_ATTRIBUTES, config, base_url, "saml_frontend")

        providers = ["foo", "bar"]
        url_map = samlfrontend.register_endpoints(providers)
        all_idp_endpoints = [get_path_from_url(v[0][0]) for v in idp_conf["service"]["idp"]["endpoints"].values()]
        compiled_regex = [re.compile(regex) for regex, _ in url_map]
        for endp in all_idp_endpoints:
            assert any(p.match(endp) for p in compiled_regex)

    def test_handle_authn_request(self, context, idp_conf, sp_conf, internal_response):
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf)
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.requester == sp_conf["entityid"]

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)

        fakesp = FakeSP(SPConfig().load(sp_conf, metadata_construction=False))
        resp = fakesp.parse_authn_request_response(resp_dict["SAMLResponse"][0],
                                                   BINDING_HTTP_REDIRECT)
        for key in resp.ava:
            assert USERS["testuser1"][key] == resp.ava[key]

    def test_handle_authn_request_without_name_id_policy_default_to_name_id_format_from_metadata(
            self, context, idp_conf, sp_conf):
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, nameid_format="")
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.user_id_hash_type == saml_name_id_format_to_hash_type(
            sp_conf["service"]["sp"]["name_id_format"][0])

    def test_handle_authn_request_without_name_id_policy_and_metadata_without_name_id_format(
            self, context, idp_conf, sp_conf):
        del sp_conf["service"]["sp"]["name_id_format"]
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, nameid_format="")
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.user_id_hash_type == UserIdHashType.transient

    def test_handle_authn_response_without_relay_state(self, context, idp_conf, sp_conf, internal_response):
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, relay_state=None)
        _, internal_req = samlfrontend.handle_authn_request(context, BINDING_HTTP_REDIRECT)
        assert internal_req.requester == sp_conf["entityid"]

        resp = samlfrontend.handle_authn_response(context, internal_response)
        resp_dict = parse_qs(urlparse(resp.message).query)

        fakesp = FakeSP(SPConfig().load(sp_conf, metadata_construction=False))
        resp = fakesp.parse_authn_request_response(resp_dict["SAMLResponse"][0],
                                                   BINDING_HTTP_REDIRECT)
        for key in resp.ava:
            assert USERS["testuser1"][key] == resp.ava[key]

        assert samlfrontend.name not in context.state

    def test_get_filter_attributes_with_sp_requested_attributes_without_friendlyname(self, idp_conf):
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

        base_url = self.construct_base_url_from_entity_id(idp_conf["entityid"])
        conf = {"idp_config": idp_conf, "endpoints": ENDPOINTS}

        internal_attributes = {"attributes": {attr_name.lower(): {"saml": [attr_name]} for attr_name in
                                              ["eduPersonTargetedID", "eduPersonPrincipalName",
                                               "eduPersonAffiliation", "mail", "displayName", "sn",
                                               "givenName"]}}  # no op mapping for saml attribute names

        samlfrontend = SAMLFrontend(None, internal_attributes, conf, base_url, "saml_frontend")
        samlfrontend.register_endpoints(["testprovider"])

        internal_req = InternalRequest(saml_name_id_format_to_hash_type(NAMEID_FORMAT_PERSISTENT),
                                       "http://sp.example.com",
                                       "Example SP")
        filtered_attributes = samlfrontend._get_approved_attributes(samlfrontend.idp,
                                                                    samlfrontend.idp.config.getattr(
                                                                        "policy", "idp"),
                                                                    internal_req.requester, None)

        assert set(filtered_attributes) == set(["edupersontargetedid", "edupersonprincipalname",
                                                "edupersonaffiliation", "mail", "displayname", "sn", "givenname"])

    def test_acr_mapping_in_authn_response(self, context, idp_conf, sp_conf, internal_response):
        eidas_loa_low = "http://eidas.europa.eu/LoA/low"
        loa = {"": eidas_loa_low}
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, extra_config={"acr_mapping": loa})
        idp_metadata_str = create_metadata_from_config_dict(samlfrontend.idp_config)

        resp = self.get_auth_response(samlfrontend, context, internal_response, sp_conf, idp_metadata_str)
        assert len(resp.assertion.authn_statement) == 1
        authn_context_class_ref = resp.assertion.authn_statement[0].authn_context.authn_context_class_ref
        assert authn_context_class_ref.text == eidas_loa_low

    def test_acr_mapping_per_idp_in_authn_response(self, context, idp_conf, sp_conf, internal_response):
        expected_loa = "LoA1"
        loa = {"": "http://eidas.europa.eu/LoA/low", idp_conf["entityid"]: expected_loa}
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, extra_config={"acr_mapping": loa})
        idp_metadata_str = create_metadata_from_config_dict(samlfrontend.idp_config)

        resp = self.get_auth_response(samlfrontend, context, internal_response, sp_conf, idp_metadata_str)
        assert len(resp.assertion.authn_statement) == 1
        authn_context_class_ref = resp.assertion.authn_statement[0].authn_context.authn_context_class_ref
        assert authn_context_class_ref.text == expected_loa

    @pytest.mark.parametrize("entity_category, entity_category_module, expected_attributes", [
        ([""], "swamid", swamid.RELEASE[""]),
        ([COCO], "edugain", edugain.RELEASE[""] + edugain.RELEASE[COCO]),
        ([RESEARCH_AND_SCHOLARSHIP], "refeds", refeds.RELEASE[""] + refeds.RELEASE[RESEARCH_AND_SCHOLARSHIP]),
        ([RESEARCH_AND_EDUCATION, EU], "swamid", swamid.RELEASE[""] + swamid.RELEASE[(RESEARCH_AND_EDUCATION, EU)]),
        ([RESEARCH_AND_EDUCATION, HEI], "swamid", swamid.RELEASE[""] + swamid.RELEASE[(RESEARCH_AND_EDUCATION, HEI)]),
        ([RESEARCH_AND_EDUCATION, NREN], "swamid", swamid.RELEASE[""] + swamid.RELEASE[(RESEARCH_AND_EDUCATION, NREN)]),
        ([SFS_1993_1153], "swamid", swamid.RELEASE[""] + swamid.RELEASE[SFS_1993_1153]),
    ])
    def test_respect_sp_entity_categories(self, context, entity_category, entity_category_module, expected_attributes,
                                          idp_conf, sp_conf, internal_response):
        idp_metadata_str = create_metadata_from_config_dict(idp_conf)
        idp_conf["service"]["idp"]["policy"]["default"]["entity_categories"] = [entity_category_module]
        if all(entity_category):  # don't insert empty entity category
            sp_conf["entity_category"] = entity_category
        if entity_category == [COCO]:
            sp_conf["service"]["sp"]["required_attributes"] = expected_attributes

        expected_attributes_in_all_entity_categories = list(
            itertools.chain(swamid.RELEASE[""], edugain.RELEASE[COCO], refeds.RELEASE[RESEARCH_AND_SCHOLARSHIP],
                            swamid.RELEASE[(RESEARCH_AND_EDUCATION, EU)], swamid.RELEASE[(RESEARCH_AND_EDUCATION, HEI)],
                            swamid.RELEASE[(RESEARCH_AND_EDUCATION, NREN)], swamid.RELEASE[SFS_1993_1153]))
        attribute_mapping = {}
        for expected_attribute in expected_attributes_in_all_entity_categories:
            attribute_mapping[expected_attribute.lower()] = {"saml": [expected_attribute]}

        internal_attributes = dict(attributes=attribute_mapping)
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, internal_attributes=internal_attributes)

        user_attributes = {k: "foo" for k in expected_attributes_in_all_entity_categories}
        internal_response.attributes = AttributeMapper(internal_attributes).to_internal("saml", user_attributes)
        internal_response.requester = sp_conf["entityid"]

        resp = self.get_auth_response(samlfrontend, context, internal_response, sp_conf, idp_metadata_str)
        assert Counter(resp.ava.keys()) == Counter(expected_attributes)

    def test_sp_metadata_including_uiinfo_display_name(self, context, idp_conf, sp_conf):
        sp_conf["service"]["sp"]["ui_info"] = dict(display_name="Test SP")
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf)
        display_names = samlfrontend._get_sp_display_name(samlfrontend.idp, sp_conf["entityid"])
        assert display_names[0]["text"] == "Test SP"

    def test_sp_metadata_including_uiinfo_without_display_name(self, context, idp_conf, sp_conf):
        sp_conf["service"]["sp"]["ui_info"] = dict(information_url="http://info.example.com")
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf)
        assert samlfrontend._get_sp_display_name(samlfrontend.idp, sp_conf["entityid"]) is None

    def test_sp_metadata_without_uiinfo(self, context, idp_conf, sp_conf):
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf)
        assert samlfrontend._get_sp_display_name(samlfrontend.idp, sp_conf["entityid"]) is None

    def test_metadata_endpoint(self, context, idp_conf):
        conf = {"idp_config": idp_conf, "endpoints": ENDPOINTS}
        samlfrontend = SAMLFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES, conf, "base_url", "saml_frontend")
        samlfrontend.register_endpoints(["todo"])
        resp = samlfrontend._metadata_endpoint(context)
        headers = dict(resp.headers)
        assert headers["Content-Type"] == "text/xml"
        assert idp_conf["entityid"] in resp.message

    def test_custom_attribute_release_with_less_attributes_than_entity_category(self, context, idp_conf, sp_conf,
                                                                                internal_response):
        idp_metadata_str = create_metadata_from_config_dict(idp_conf)
        idp_conf["service"]["idp"]["policy"]["default"]["entity_categories"] = ["swamid"]
        sp_conf["entity_category"] = [SFS_1993_1153]
        expected_attributes = swamid.RELEASE[SFS_1993_1153]

        attribute_mapping = {}
        for expected_attribute in expected_attributes:
            attribute_mapping[expected_attribute.lower()] = {"saml": [expected_attribute]}
        internal_attributes = dict(attributes=attribute_mapping)

        user_attributes = {k: "foo" for k in expected_attributes}
        internal_response.attributes = AttributeMapper(internal_attributes).to_internal("saml", user_attributes)

        custom_attributes = {idp_conf["entityid"]: {sp_conf["entityid"]: {"exclude": ["norEduPersonNIN"]}}}
        samlfrontend = self.setup_for_authn_req(context, idp_conf, sp_conf, internal_attributes=internal_attributes,
                                                extra_config=dict(custom_attribute_release=custom_attributes))

        resp = self.get_auth_response(samlfrontend, context, internal_response, sp_conf, idp_metadata_str)
        assert len(resp.ava.keys()) == 0


class TestSAMLMirrorFrontend:
    BACKEND = "test_backend"
    TARGET_ENTITY_ID = "target-idp.entity_id"

    @pytest.fixture(autouse=True)
    def create_frontend(self, idp_conf):
        conf = {"idp_config": idp_conf, "endpoints": ENDPOINTS}
        self.frontend = SAMLMirrorFrontend(lambda ctx, req: None, INTERNAL_ATTRIBUTES, conf, BASE_URL,
                                           "saml_mirror_frontend")
        self.frontend.register_endpoints([self.BACKEND])

    def assert_dynamic_endpoints(self, sso_endpoints):
        endpoint_base_url = "{}/{}/{}".format(BASE_URL, self.BACKEND, self.TARGET_ENTITY_ID)
        expected_endpoints = []
        for binding, endpoint in ENDPOINTS["single_sign_on_service"].items():
            endp = "{}/{}".format(endpoint_base_url, endpoint)
            expected_endpoints.append((endp, binding))

        assert all(sso in sso_endpoints for sso in expected_endpoints)

    def test_load_endpoints_to_config(self):
        idp_config = self.frontend._load_endpoints_to_config(self.BACKEND, self.TARGET_ENTITY_ID)
        self.assert_dynamic_endpoints(idp_config["service"]["idp"]["endpoints"]["single_sign_on_service"])

    def test_load_idp_dynamic_endpoints(self, context):
        context.path = "{}/{}/sso/redirect".format(self.BACKEND, self.TARGET_ENTITY_ID)
        context.target_backend = self.BACKEND
        idp = self.frontend._load_idp_dynamic_endpoints(context)
        self.assert_dynamic_endpoints(idp.config._idp_endpoints["single_sign_on_service"])

    def test_load_idp_dynamic_entity_id(self, idp_conf):
        state = State()
        state[self.frontend.name] = {"target_entity_id": self.TARGET_ENTITY_ID}
        idp = self.frontend._load_idp_dynamic_entity_id(state)
        assert idp.config.entityid == "{}/{}".format(idp_conf["entityid"], self.TARGET_ENTITY_ID)


class TestSamlNameIdFormatToHashType:
    def test_should_default_to_transient(self):
        assert saml_name_id_format_to_hash_type("foobar") == UserIdHashType.transient

    def test_should_map_transient(self):
        assert saml_name_id_format_to_hash_type(NAMEID_FORMAT_TRANSIENT) == UserIdHashType.transient

    def test_should_map_persistent(self):
        assert saml_name_id_format_to_hash_type(NAMEID_FORMAT_PERSISTENT) == UserIdHashType.persistent


class TestSamlHashTypeToNameIdFormat:
    def test_should_fail_unknown(self):
        with pytest.raises(SATOSAModuleError):
            hash_type_to_saml_name_id_format(UserIdHashType.public)

    def test_should_map_transient(self):
        assert hash_type_to_saml_name_id_format(UserIdHashType.transient) == NAMEID_FORMAT_TRANSIENT

    def test_should_map_persistent(self):
        assert hash_type_to_saml_name_id_format(UserIdHashType.persistent) == NAMEID_FORMAT_PERSISTENT

    def test_should_map_email(self):
        assert hash_type_to_saml_name_id_format(UserIdHashType.public_email) == NAMEID_FORMAT_EMAILADDRESS

    def test_should_map_none_to_unspecified(self):
        assert hash_type_to_saml_name_id_format(None) == NAMEID_FORMAT_UNSPECIFIED
