#!/usr/bin/env python
"""
A saml2 backend module for the satosa proxy
"""
import copy
import logging
from urllib.parse import urlparse

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.client_base import Base
from saml2.config import SPConfig

from saml2.metadata import create_metadata_string

from saml2.samlp import NameIDPolicy

from satosa.backends.base import BackendModule
from satosa.exception import SATOSAAuthenticationError
from satosa.internal_data import UserIdHashType, InternalRequest, InternalResponse, \
    AuthenticationInformation, DataConverter
from satosa.logging import satosa_logging
from satosa.response import SeeOther, Response
from satosa.util import rndstr, get_saml_name_id_format, saml_name_format_to_hash_type

LOGGER = logging.getLogger(__name__)


class MetadataResponse(Response):
    """
    A response containing metadata for the saml backend
    """

    def __init__(self, config):
        """
        Creates a response containing the metadata generated from the SP config.
        :type config: dict[str, Any]
        :param config: The SP config
        """
        metadata_string = create_metadata_string(None, config, 4, None, None, None, None,
                                                 None).decode("utf-8")
        resp = {"content": "text/xml"}
        super(MetadataResponse, self).__init__(message=metadata_string, **resp)


class SamlBackend(BackendModule):
    """
    A saml2 backend module
    """
    STATE_KEY = "Saml2B_76ASF"

    def __init__(self, outgoing, internal_attributes, config):
        """
        :type outgoing:
        (satosa.context.Context, satosa.internal_data.InternalResponse) -> satosa.response.Response
        :type internal_attributes: dict[str, dict[str, list[str] | str]]
        :type config: dict[str, Any]

        :param outgoing: Callback should be called by the module after
                                   the authorization in the backend is done.
        :param internal_attributes: Internal attribute map
        :param config: The module config
        """
        super(SamlBackend, self).__init__(outgoing, internal_attributes)
        sp_config = SPConfig().load(copy.deepcopy(config["config"]), False)

        self.sp = Base(sp_config)
        self.idp_disco_query_param = "entityID"
        self.config = config
        self.bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
        self.discosrv = None
        self.converter = DataConverter(internal_attributes)
        try:
            self.discosrv = config["disco_srv"]
        except KeyError:
            pass

    @staticmethod
    def create_name_id_policy(usr_id_hash_type):
        """
        Creates a name id policy

        :type usr_id_hash_type: satosa.internal_data.UserIdHashType
        :rtype: saml2.samlp.NameIDPolicy

        :param usr_id_hash_type: The internal id hash type
        :return: A name id policy
        """
        nameid_format = get_saml_name_id_format(usr_id_hash_type)
        name_id_policy = NameIDPolicy(format=nameid_format)
        return name_id_policy

    def start_auth(self, context, internal_req):
        """
        See super class method satosa.backends.base.BackendModule#start_auth
        :type context: satosa.context.Context
        :type internal_req: satosa.internal_data.InternalRequest
        :rtype: satosa.response.Response
        """
        try:
            entity_id = context.internal_data["saml2.target_entity_id"]
            return self.authn_request(context, entity_id, internal_req)
        except KeyError:
            return self.disco_query(context, internal_req)

    def disco_query(self, context, internal_req):
        """
        Makes a request to the discovery server

        :type context: satosa.context.Context
        :type internal_req: satosa.internal_data.InternalRequest
        :rtype: satosa.response.SeeOther

        :param context: The current context
        :param internal_req: The request
        :return: Response
        """
        state = context.state
        if internal_req.user_id_hash_type:
            state.add(SamlBackend.STATE_KEY, internal_req.user_id_hash_type.name)

        _cli = self.sp

        eid = _cli.config.entityid
        # returns list of 2-tuples
        disco_resp = _cli.config.getattr("endpoints", "sp")["discovery_response"]
        # The first value of the first tuple is the one I want
        ret = disco_resp[0][0]
        loc = _cli.create_discovery_service_request(self.discosrv, eid,
                                                    **{"return": ret})
        return SeeOther(loc)

    def authn_request(self, context, entity_id, internal_req):
        """
        Do an authorization request on idp with given entity id.
        This is the start of the authorization.

        :type context: satosa.context.Context
        :type entity_id: str
        :type internal_req: satosa.internal_data.InternalRequest
        :rtype: satosa.response.Response

        :param context: The curretn context
        :param entity_id: Target IDP entity id
        :param internal_req: The request
        :return: Response
        """
        _cli = self.sp
        req_args = {"name_id_policy": self.create_name_id_policy(internal_req.user_id_hash_type)}

        state = context.state

        try:
            # Picks a binding to use for sending the Request to the IDP
            _binding, destination = _cli.pick_binding(
                "single_sign_on_service", self.bindings, "idpsso",
                entity_id=entity_id)
            satosa_logging(LOGGER, logging.DEBUG,
                           "binding: %s, destination: %s" % (_binding, destination), state)
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
            satosa_logging(LOGGER, logging.DEBUG, "ht_args: %s" % ht_args, state)
        except Exception as exc:
            satosa_logging(LOGGER, logging.DEBUG,
                           "Failed to construct the AuthnRequest for state: %s" % state, state,
                           exc_info=True)
            raise SATOSAAuthenticationError(state, "Failed to construct the AuthnRequest") from exc

        state.add(SamlBackend.STATE_KEY, relay_state)

        if _binding == BINDING_HTTP_REDIRECT:
            for param, value in ht_args["headers"]:
                if param == "Location":
                    resp = SeeOther(str(value))
                    break
            else:
                satosa_logging(LOGGER, logging.DEBUG, "Parameter error for state: %s" % state,
                               state)
                raise SATOSAAuthenticationError(state, "Parameter error")
        else:
            resp = Response(ht_args["data"], headers=ht_args["headers"])

        return resp

    def authn_response(self, context, binding):
        """
        Endpoint for the idp response
        :type context: satosa.context,Context
        :type binding: str
        :rtype: satosa.response.Response

        :param context: The current context
        :param binding: The saml binding type
        :return: response
        """
        _authn_response = context.request

        state = context.state

        if not _authn_response["SAMLResponse"]:
            satosa_logging(LOGGER, logging.DEBUG, "Missing Response for state: %s" % state, state)
            raise SATOSAAuthenticationError(state, "Missing Response")

        try:
            _response = self.sp.parse_authn_request_response(
                _authn_response["SAMLResponse"], binding)
        except Exception as err:
            satosa_logging(LOGGER, logging.DEBUG,
                           "Failed to parse authn request for state: %s" % state, state,
                           exc_info=True)
            raise SATOSAAuthenticationError(state, "Failed to parse authn request") from err

        # check if the relay_state matches the cookie state
        if state.get(SamlBackend.STATE_KEY) != _authn_response['RelayState']:
            satosa_logging(LOGGER, logging.DEBUG,
                           "State did not match relay state for state: %s" % state, state)
            raise SATOSAAuthenticationError(state, "State did not match relay state")

        return self.auth_callback_func(context, self._translate_response(_response))

    def disco_response(self, context):
        """
        Endpoint for the discovery server response

        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The current context
        :return: response
        """
        info = context.request

        state = context.state

        try:
            entity_id = info[self.idp_disco_query_param]
        except KeyError as err:
            satosa_logging(LOGGER, logging.DEBUG, "No IDP chosen for state %s" % state, state,
                           exc_info=True)
            raise SATOSAAuthenticationError(state, "No IDP chosen") from err
        else:
            request_info = InternalRequest(
                getattr(UserIdHashType, state.get(SamlBackend.STATE_KEY)), None)
            return self.authn_request(context, entity_id, request_info)

    def _translate_response(self, response):
        """
        Translates a saml authorization response to an internal response

        :type response: saml2.response.AuthnResponse
        :rtype: satosa.internal_data.InternalResponse
        :param response: The saml authorization response
        :return: A translated internal response
        """
        _authn_info = response.authn_info()[0]
        user_id_hash_type = saml_name_format_to_hash_type(response.name_id.format)
        timestamp = response.assertion.authn_statement[0].authn_instant
        issuer = _authn_info[1][0]
        auth_class_ref = _authn_info[0]

        auth_info = AuthenticationInformation(auth_class_ref, timestamp, issuer)
        internal_resp = InternalResponse(user_id_hash_type, auth_info=auth_info)

        internal_resp.set_user_id(response.get_subject().text)

        internal_resp.add_attributes(self.converter.to_internal("saml", response.ava))
        return internal_resp

    def _metadata(self, context):
        """
        Endpoint for retrieving the backend metadata
        :type context: satosa.context.Context
        :rtype: satosa.backends.saml2.MetadataResponse

        :param context: The current context
        :return: response with metadata
        """
        satosa_logging(LOGGER, logging.DEBUG, "Sending metadata response", context.state)
        return MetadataResponse(self.sp.config)

    def register_endpoints(self):
        """
        See super class method satosa.backends.base.BackendModule#register_endpoints
        :rtype list[(str, ((satosa.context.Context, Any) -> Any, Any))]
        """
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
            url_map.append(("^%s$" % metadata_path.path[1:], self._metadata))

        if self.discosrv:
            for endp, binding in sp_endpoints["discovery_response"]:
                parsed_endp = urlparse(endp)
                url_map.append(
                    ("^%s$" % parsed_endp.path[1:], self.disco_response))

        return url_map
