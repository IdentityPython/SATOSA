#!/usr/bin/env python
import copy
import logging
from urllib.parse import urlparse

from saml2.config import IdPConfig
from saml2.httputil import ServiceError
from saml2.httputil import Response
from saml2.httputil import Redirect
from saml2.httputil import Unauthorized
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.saml import NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT, NameID
from saml2.samlp import authn_request_from_string

from saml2.server import Server

from satosa.frontends.base import FrontendModule
from satosa.internal_data import UserIdHashType, InternalRequest
import satosa.service as service
from satosa.service import response
from satosa.state import State

logger = logging.getLogger(__name__)


class SamlFrontend(FrontendModule):
    STATE_KEY = "SamlF_HY34CV"

    def __init__(self, auth_req_callback_func, conf):
        if conf is None:
            raise TypeError("conf can't be 'None'")
        self._validate_config(conf)

        super(SamlFrontend, self).__init__(auth_req_callback_func)
        self.config = conf["idp_config"]
        self.endpoints = conf["endpoints"]
        self.base = conf["base"]
        self.response_bindings = None
        self.idp = None

    @staticmethod
    def name_format_to_hash_type(name_format):
        if name_format == NAMEID_FORMAT_TRANSIENT:
            return UserIdHashType.transient
        elif name_format == NAMEID_FORMAT_PERSISTENT:
            return UserIdHashType.persistent
        return None

    @staticmethod
    def get_name_id_format(hash_type):
        if hash_type == UserIdHashType.transient:
            return NAMEID_FORMAT_TRANSIENT
        elif hash_type == UserIdHashType.persistent:
            return NAMEID_FORMAT_PERSISTENT
        return None

    def save_state(self, context, _dict, _request):
        return {"origin_authn_req": _dict["authn_req"].to_string().decode("utf-8"),
                "relay_state": _request["RelayState"]}

    def load_state(self, state):
        return state.get(SamlFrontend.STATE_KEY)

    def _validate_config(self, config):
        mandatory_keys = ["idp_config", "endpoints", "base"]
        for key in mandatory_keys:
            assert key in config, "Missing key '%s' in config" % key

    def verify_request(self, idp, query, binding):
        if not query:
            logger.info("Missing QUERY")
            resp = Unauthorized('Unknown user')
            return {"response": resp}

        req_info = idp.parse_authn_request(query, binding)

        logger.info("parsed OK")
        _authn_req = req_info.message
        logger.debug("%s", _authn_req)

        # Check that I know where to send the reply to
        try:
            binding_out, destination = idp.pick_binding(
                "assertion_consumer_service",
                bindings=self.response_bindings,
                entity_id=_authn_req.issuer.text, request=_authn_req)
        except Exception as err:
            logger.error("Couldn't find receiver endpoint: %s", err)
            raise

        logger.debug("Binding: %s, destination: %s", binding_out, destination)

        resp_args = {}
        try:
            resp_args = idp.response_args(_authn_req)
            _resp = None
        except UnknownPrincipal as excp:
            _resp = idp.create_error_response(_authn_req.id,
                                              destination, excp)
        except UnsupportedBinding as excp:
            _resp = idp.create_error_response(_authn_req.id,
                                              destination, excp)

        req_args = {}
        for key in ["subject", "name_id_policy", "conditions",
                    "requested_authn_context", "scoping", "force_authn",
                    "is_passive"]:
            try:
                val = getattr(_authn_req, key)
            except AttributeError:
                pass
            else:
                if val is not None:
                    req_args[key] = val

        return {"resp_args": resp_args, "response": _resp,
                "authn_req": _authn_req, "req_args": req_args}

    def _handle_authn_request(self, context, binding_in, idp):
        _request = context.request
        _binding_in = service.INV_BINDING_MAP[binding_in]

        try:
            _dict = self.verify_request(idp, _request["SAMLRequest"],
                                        _binding_in)
        except UnknownPrincipal as excp:
            logger.error("UnknownPrincipal: %s", excp)
            return ServiceError("UnknownPrincipal: %s" % (excp,))
        except UnsupportedBinding as excp:
            logger.error("UnsupportedBinding: %s", excp)
            return ServiceError("UnsupportedBinding: %s" % (excp,))

        _binding = _dict["resp_args"]["binding"]
        if _dict["response"]:  # An error response
            http_args = idp.apply_binding(
                _binding, "%s" % _dict["response"],
                _dict["resp_args"]["destination"],
                _request["RelayState"], response=True)

            logger.debug("HTTPargs: %s", http_args)
            return response(_binding, http_args)
        else:

            try:
                context.internal_data["saml2.target_entity_id"] = _request["entityID"]
            except KeyError:
                pass

            request_state = self.save_state(context, _dict, _request)
            # state = urlsafe_b64encode(json.dumps(request_state).encode("UTF-8")).decode("UTF-8")
            state = State()
            state.add(SamlFrontend.STATE_KEY, request_state)

            internal_req = InternalRequest(self.name_format_to_hash_type(_dict['req_args']['name_id_policy'].format),
                                           _dict["resp_args"]["sp_entity_id"])

            idp_policy = idp.config.getattr("policy", "idp")
            if idp_policy:
                entity_categories = idp_policy.get_entity_categories(
                    _dict["resp_args"]["sp_entity_id"], idp.metadata)
                attribute_filter = list(entity_categories.keys())
                internal_req.add_pysaml_attr_filter(attribute_filter)

            return self.auth_req_callback_func(context, internal_req, state)

    def handle_authn_request(self, context, binding_in):
        return self._handle_authn_request(context, binding_in, self.idp)

    def _handle_authn_response(self, context, internal_response, state, idp):
        request_state = self.load_state(state)
        origin_authn_req = authn_request_from_string(request_state["origin_authn_req"])

        # Diverse arguments needed to construct the response
        resp_args = idp.response_args(origin_authn_req)

        ava = internal_response.get_pysaml_attributes()
        # TODO what about authn_auth in auth_info?
        auth_info = {"class_ref": internal_response.auth_info.auth_class_ref}

        name_id = NameID(text=internal_response.user_id,
                         format=self.get_name_id_format(internal_response.user_id_hash_type),
                         sp_name_qualifier=None,
                         name_qualifier=None)

        # Will signed the response by default
        resp = self.construct_authn_response(idp,
                                             ava,
                                             name_id=name_id,
                                             authn=auth_info,
                                             resp_args=resp_args,
                                             relay_state=request_state["relay_state"],
                                             sign_response=True)

        return resp

    def handle_authn_response(self, context, internal_response, state):
        return self._handle_authn_response(context, internal_response, state, self.idp)

    def construct_authn_response(self, idp, identity, name_id, authn,
                                 resp_args,
                                 relay_state, sign_response=True):
        _resp = idp.create_authn_response(identity, name_id=name_id,
                                          authn=authn,
                                          sign_response=sign_response,
                                          **resp_args)

        http_args = idp.apply_binding(
            resp_args["binding"], "%s" % _resp, resp_args["destination"],
            relay_state, response=True)

        logger.debug("HTTPargs: %s", http_args)

        resp = None
        if http_args["data"]:
            resp = Response(http_args["data"], headers=http_args["headers"])
        else:
            for header in http_args["headers"]:
                if header[0] == "Location":
                    resp = Redirect(header[1])

        if not resp:
            resp = ServiceError("Don't know how to return response")

        return resp

    def _validate_providers(self, providers):
        if providers is None or not isinstance(providers, list):
            raise TypeError("'providers' is not 'list' type")

    def _register_endpoints(self, providers):
        url_map = []

        for endp_category in self.endpoints:
            for binding, endp in self.endpoints[endp_category].items():
                valid_providers = ""
                for provider in providers:
                    valid_providers = "{}|^{}".format(valid_providers, provider)
                valid_providers = valid_providers.lstrip("|")
                parsed_endp = urlparse(endp)
                url_map.append(("%s/%s$" % (valid_providers, parsed_endp.path),
                                (self.handle_authn_request, service.BINDING_MAP[binding])))
                url_map.append(("%s/%s/(.*)$" % (valid_providers, parsed_endp.path),
                                (self.handle_authn_request, service.BINDING_MAP[binding])))

        return url_map

    def _build_idp_config_endpoints(self, config, providers):
        # Add an endpoint to each provider
        idp_endpoints = []
        for endp_category in self.endpoints.keys():
            for func, endpoint in self.endpoints[endp_category].items():
                for provider in providers:
                    endpoint = "{base}/{provider}/{endpoint}".format(
                        base=self.base, provider=provider, endpoint=endpoint)
                    idp_endpoints.append((endpoint, func))
            config["service"]["idp"]["endpoints"][endp_category] = idp_endpoints

        return config

    def register_endpoints(self, providers):
        self._validate_providers(providers)
        self.config = self._build_idp_config_endpoints(self.config, providers)
        # Create the idp
        idp_config = IdPConfig().load(copy.deepcopy(self.config), metadata_construction=False)
        self.idp = Server(config=idp_config)
        return self._register_endpoints(providers)
