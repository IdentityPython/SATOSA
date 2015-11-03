#!/usr/bin/env python
import copy
import logging
from urllib.parse import urlparse

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.client_base import Base
from saml2.config import SPConfig
from saml2.metadata import create_metadata_string
from saml2.response import VerificationError
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.saml import NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT
from saml2.samlp import NameIDPolicy
from satosa.backends.base import BackendModule
from satosa.exception import AuthenticationError, SATOSACriticalError
from satosa.internal_data import UserIdHashType, InternalRequest, InternalResponse, \
    AuthenticationInformation
from satosa.response import SeeOther, Response
from satosa.service import rndstr
from satosa.state import state_to_cookie, cookie_to_state, StateError

LOGGER = logging.getLogger(__name__)


class MetadataResponse(Response):
    def __init__(self, config):
        metadata_string = create_metadata_string(None, config, 4, None, None, None, None,
                                                 None).decode("utf-8")
        resp = {"content": "text/xml"}
        super(MetadataResponse, self).__init__(message=metadata_string, **resp)


class SamlBackend(BackendModule):
    STATE_KEY = "Saml2B_76ASF"

    def __init__(self, outgoing, config):
        super(SamlBackend, self).__init__(outgoing)
        sp_config = SPConfig().load(copy.deepcopy(config["config"]), False)

        self.state_encryption_key = config["encryption_key"]
        self.sp = Base(sp_config)
        self.idp_disco_query_param = "entityID"
        self.config = config
        self.bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
        self.discosrv = None
        try:
            self.discosrv = config["disco_srv"]
        except KeyError:
            pass

        LOGGER.debug("--- SSO ---")

    @staticmethod
    def create_name_id_policy(usr_id_hash_type):
        nameid_format = None
        if UserIdHashType.transient == usr_id_hash_type:
            nameid_format = NAMEID_FORMAT_TRANSIENT
        elif UserIdHashType.persistent == usr_id_hash_type:
            nameid_format = NAMEID_FORMAT_PERSISTENT

        name_id_policy = NameIDPolicy(format=nameid_format)
        return name_id_policy

    @staticmethod
    def name_format_to_hash_type(name_format):
        if name_format == NAMEID_FORMAT_TRANSIENT:
            return UserIdHashType.transient
        elif name_format == NAMEID_FORMAT_PERSISTENT:
            return UserIdHashType.persistent
        return None

    def start_auth(self, context, internal_req, state):

        try:
            entity_id = context.internal_data["saml2.target_entity_id"]
            return self.authn_request(context, entity_id, internal_req, state)
        except KeyError:
            return self.disco_query(context, internal_req, state)

    def disco_query(self, context, internal_req, state):
        if internal_req.user_id_hash_type:
            state.add(SamlBackend.STATE_KEY, internal_req.user_id_hash_type.name)

        _cli = self.sp

        eid = _cli.config.entityid
        # returns list of 2-tuples
        disco_resp = _cli.config.getattr("endpoints", "sp")["discovery_response"]
        # The first value of the first tuple is the one I want
        ret = disco_resp[0][0]
        state_cookie = state_to_cookie(state, "saml2_backend_disco_state", "/", self.state_encryption_key)
        loc = _cli.create_discovery_service_request(self.discosrv, eid,
                                                    **{"return": ret})
        return SeeOther(loc, state_cookie)

    def authn_request(self, context, entity_id, internal_req, state):
        _cli = self.sp
        req_args = {"name_id_policy": self.create_name_id_policy(internal_req.user_id_hash_type)}

        try:
            # Picks a binding to use for sending the Request to the IDP
            _binding, destination = _cli.pick_binding(
                "single_sign_on_service", self.bindings, "idpsso",
                entity_id=entity_id)
            LOGGER.debug("binding: %s, destination: %s" % (_binding,
                                                           destination))
            # Binding here is the response binding that is which binding the
            # IDP should use to return the response.
            acs = _cli.config.getattr("endpoints", "sp")[
                "assertion_consumer_service"]
            # just pick one
            endp, return_binding = acs[0]
            req_id, req = _cli.create_authn_request(destination,
                                                    binding=return_binding,
                                                    **req_args)
            relay_state = rndstr()
            ht_args = _cli.apply_binding(_binding, "%s" % req, destination, relay_state=relay_state)
            LOGGER.debug("ht_args: %s" % ht_args)
        except Exception as exc:
            LOGGER.exception(exc)
            raise AuthenticationError(state, "Failed to construct the AuthnRequest: %s" % exc)

        state.add(SamlBackend.STATE_KEY, relay_state)

        state_cookie = state_to_cookie(state, "saml2_backend_state", "/", self.state_encryption_key)
        if _binding == BINDING_HTTP_REDIRECT:
            for param, value in ht_args["headers"]:
                if param == "Location":
                    resp = SeeOther(str(value), state_cookie)
                    break
            else:
                raise AuthenticationError(state, "Parameter error")
        else:
            resp = Response(ht_args["data"], cookie=state_cookie, headers=ht_args["headers"])

        return resp

    def authn_response(self, context, binding):
        _authn_response = context.request

        try:
            state = cookie_to_state(context.cookie, "saml2_backend_state", self.state_encryption_key)
        except StateError as error:
            # TODO LOG
            raise SATOSACriticalError("Missing state in authn_response")

        if not _authn_response["SAMLResponse"]:
            LOGGER.info("Missing Response")
            raise AuthenticationError(state, 'Unknown user')

        try:
            _response = self.sp.parse_authn_request_response(
                _authn_response["SAMLResponse"], binding)
        except UnknownPrincipal as excp:
            LOGGER.error("UnknownPrincipal: %s", excp)
            raise AuthenticationError(state, "UnknownPrincipal: %s" % (excp,))
        except UnsupportedBinding as excp:
            LOGGER.error("UnsupportedBinding: %s", excp)
            raise AuthenticationError(state, "UnsupportedBinding: %s" % (excp,))
        except VerificationError as err:
            raise AuthenticationError(state, "Verification error: %s" % (err,))
        except Exception as err:
            raise AuthenticationError(state, "Other error: %s" % (err,))

        # check if the relay_state matches the cookie state
        if state.get(SamlBackend.STATE_KEY) != _authn_response['RelayState']:
            raise AuthenticationError(state, "State did not match relay state")

        return self.auth_callback_func(context,
                                       self._translate_response(_response),
                                       state)

    def disco_response(self, context, *args):
        info = context.request

        try:
            state = cookie_to_state(context.cookie, "saml2_backend_disco_state", self.state_encryption_key)
        except StateError as error:
            # TODO LOG
            raise SATOSACriticalError("Missing state in disco_response")

        try:
            entity_id = info[self.idp_disco_query_param]
        except KeyError:
            raise AuthenticationError(state, "You must chose an IdP")
        else:
            request_info = InternalRequest(
                getattr(UserIdHashType, state.get(SamlBackend.STATE_KEY)), None)
            return self.authn_request(context, entity_id, request_info, state)

    def _translate_response(self, response):
        _authn_info = response.authn_info()[0]
        user_id_hash_type = self.name_format_to_hash_type(response.name_id.format)
        timestamp = response.assertion.authn_statement[0].authn_instant
        issuer = _authn_info[1][0]
        auth_class_ref = _authn_info[0]

        auth_info = AuthenticationInformation(auth_class_ref, timestamp, issuer)
        internal_resp = InternalResponse(user_id_hash_type, auth_info=auth_info)
        internal_resp.add_pysaml_attributes(response.ava)
        internal_resp.user_id = response.get_subject().text
        return internal_resp

    def _metadata(self, context, *args):
        return MetadataResponse(self.sp.config)

    def register_endpoints(self):
        url_map = []
        sp_endpoints = self.sp.config.getattr("endpoints", "sp")
        for endp, binding in sp_endpoints["assertion_consumer_service"]:
            parsed_endp = urlparse(endp)
            url_map.append(
                ("^%s?(.*)$" % parsed_endp.path[1:], (self.authn_response, binding)))
            url_map.append(
                ("^%s$" % parsed_endp.path[1:], (self.authn_response, binding)))

        if "publish_metadata" in self.config:
            metadata_path = urlparse(self.config["publish_metadata"])
            url_map.append(("^%s$" % metadata_path.path[1:], (self._metadata, "")))

        if self.discosrv:
            for endp, binding in sp_endpoints["discovery_response"]:
                parsed_endp = urlparse(endp)
                url_map.append(
                    ("^%s$" % parsed_endp.path[1:], (self.disco_response, binding)))

        return url_map
