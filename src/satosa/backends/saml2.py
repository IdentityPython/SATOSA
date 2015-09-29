#!/usr/bin/env python
from base64 import urlsafe_b64encode, urlsafe_b64decode
import copy
import json
import logging
from urllib.parse import urlparse

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.client_base import Base
from saml2.httputil import ServiceError, SeeOther, Response
from saml2.config import SPConfig
from saml2.httputil import Unauthorized
from saml2.metadata import create_metadata_string
from saml2.response import VerificationError
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.samlp import name_id_policy_from_string
from satosa import VALID_ATTRIBUTES
from satosa.backends.base import BackendModule

from satosa.service import BINDING_MAP, response
import satosa.service as service

LOGGER = logging.getLogger(__name__)


class MetadataResponse(Response):
    def __init__(self, config):
        metadata_string = create_metadata_string(None, config, 4, None, None, None, None,
                                                 None).decode("utf-8")
        resp = {"content": "text/xml"}
        super(MetadataResponse, self).__init__(message=metadata_string, **resp)


class SamlBackend(BackendModule):
    def __init__(self, outgoing, config):
        super(SamlBackend, self).__init__(outgoing)
        sp_config = SPConfig().load(copy.deepcopy(config), False)

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

    def start_auth(self, context, request_info, state):

        try:
            entity_id = context.internal_data["saml2.target_entity_id"]
            return self.authn_request(context, entity_id, request_info, state)
        except KeyError:
            return self.disco_query(context, request_info, state)

    def disco_query(self, context, request_info, state):
        disco_state = {"state": state, }
        if "req_args" in request_info and "name_id_policy" in request_info["req_args"]:
            disco_state["req_args"] = {
                "name_id_policy":
                    request_info["req_args"]["name_id_policy"].to_string().decode("utf-8")}

        disco_state = urlsafe_b64encode(json.dumps(disco_state).encode("utf-8")).decode("utf-8")

        _cli = self.sp

        eid = _cli.config.entityid
        # returns list of 2-tuples
        disco_resp = _cli.config.getattr("endpoints", "sp")["discovery_response"]
        # The first value of the first tuple is the one I want
        ret = disco_resp[0][0]
        # append it to the disco server URL
        ret += "?state=%s" % disco_state
        # ret += "?%s" % disco_state
        loc = _cli.create_discovery_service_request(self.discosrv, eid,
                                                    **{"return": ret})

        return SeeOther(loc)

    def authn_request(self, context, entity_id, request_info, state):
        _cli = self.sp
        req_args = request_info["req_args"]
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

            ht_args = _cli.apply_binding(_binding, "%s" % req, destination,
                                         relay_state=state)
            LOGGER.debug("ht_args: %s" % ht_args)
        except Exception as exc:
            LOGGER.exception(exc)
            return ServiceError("Failed to construct the AuthnRequest: %s" % exc)

        return response(_binding, ht_args)

    def authn_response(self, context, binding):
        _authn_response = context.request

        if not _authn_response["SAMLResponse"]:
            LOGGER.info("Missing Response")
            return Unauthorized('Unknown user')

        binding = service.INV_BINDING_MAP[binding]
        try:
            _response = self.sp.parse_authn_request_response(
                _authn_response["SAMLResponse"], binding)
        except UnknownPrincipal as excp:
            LOGGER.error("UnknownPrincipal: %s", excp)
            return ServiceError("UnknownPrincipal: %s" % (excp,))
        except UnsupportedBinding as excp:
            LOGGER.error("UnsupportedBinding: %s", excp)
            return ServiceError("UnsupportedBinding: %s" % (excp,))
        except VerificationError as err:
            return ServiceError("Verification error: %s" % (err,))
        except Exception as err:
            return ServiceError("Other error: %s" % (err,))

        return self.auth_callback_func(context,
                                       self._translate_response(_response),
                                       _authn_response['RelayState'])

    def disco_response(self, context, *args):
        info = context.request
        state = urlsafe_b64decode(info["state"].encode("utf-8")).decode("utf-8")
        try:
            entity_id = info[self.idp_disco_query_param]
        except KeyError:
            return Unauthorized("You must chose an IdP")
        else:
            state = json.loads(state)
            if "req_args" in state and "name_id_policy" in state["req_args"]:
                state["req_args"]["name_id_policy"] = name_id_policy_from_string(
                    state["req_args"]["name_id_policy"])

            return self.authn_request(context, entity_id, state, state["state"])

    def _translate_response(self, response):
        translated_response = {}
        translated_params = {}
        for param in VALID_ATTRIBUTES:
            try:
                translated_params[param] = response.ava[param]
            except KeyError:
                pass
        translated_response["ava"] = translated_params
        translated_response["name_id"] = response.get_subject()
        _authn_info = response.authn_info()[0]
        translated_response["auth_info"] = {"class_ref": _authn_info[0],
                                            "authn_auth": _authn_info[1][0]}
        return translated_response

    def _metadata(self, context, *args):
        return MetadataResponse(self.sp.config)

    def register_endpoints(self):
        url_map = []
        sp_endpoints = self.sp.config.getattr("endpoints", "sp")
        for endp, binding in sp_endpoints["assertion_consumer_service"]:
            parsed_endp = urlparse(endp)
            url_map.append(
                ("^%s?(.*)$" % parsed_endp.path[1:], (self.authn_response, BINDING_MAP[binding])))
            url_map.append(
                ("^%s$" % parsed_endp.path[1:], (self.authn_response, BINDING_MAP[binding])))

        try:
            metadata_path = urlparse(self.config["publish_metadata"])
            url_map.append(("^%s$" % metadata_path.path[1:], (self._metadata, "")))
        except KeyError:
            pass

        if self.discosrv:
            for endp, binding in sp_endpoints["discovery_response"]:
                parsed_endp = urlparse(endp)
                url_map.append(
                    ("^%s$" % parsed_endp.path[1:], (self.disco_response, BINDING_MAP[binding])))

        return url_map
