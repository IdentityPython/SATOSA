#!/usr/bin/env python
from base64 import urlsafe_b64decode, urlsafe_b64encode
import copy
import json
import logging
from urllib.parse import urlparse
from saml2.config import IdPConfig

from saml2.httputil import ServiceError
from saml2.httputil import Response
from saml2.httputil import Redirect
from saml2.httputil import Unauthorized
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.samlp import authn_request_from_string
from saml2.server import Server
from satosa.frontends.base import FrontendBase

import satosa.service as service
from satosa.service import response

LOGGER = logging.getLogger(__name__)


class SamlIDP(FrontendBase):
    def __init__(self, auth_req_callback_func, conf):
        """
        Constructor for the class.
        :param environ: WSGI environ
        :param start_response: WSGI start response function
        :param conf: The SAML configuration
        :param cache: Cache with active sessions
        """
        super(SamlIDP, self).__init__(auth_req_callback_func)
        self.config = conf["idp_config"]
        self.endpoints = conf["endpoints"]
        self.base = conf["base"]
        self.response_bindings = None

    def verify_request(self, idp, query, binding):
        """ Parses and verifies the SAML Authentication Request

        :param query: The SAML authn request, transport encoded
        :param binding: Which binding the query came in over
        :returns: dictionary
        """

        if not query:
            LOGGER.info("Missing QUERY")
            resp = Unauthorized('Unknown user')
            return {"response": resp}

        req_info = idp.parse_authn_request(query, binding)

        LOGGER.info("parsed OK")
        _authn_req = req_info.message
        LOGGER.debug("%s", _authn_req)

        # Check that I know where to send the reply to
        try:
            binding_out, destination = idp.pick_binding(
                "assertion_consumer_service",
                bindings=self.response_bindings,
                entity_id=_authn_req.issuer.text, request=_authn_req)
        except Exception as err:
            LOGGER.error("Couldn't find receiver endpoint: %s", err)
            raise

        LOGGER.debug("Binding: %s, destination: %s", binding_out, destination)

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

    def handle_authn_request(self, context, binding_in):
        """
        Deal with an authentication request

        :param binding_in: Which binding was used when receiving the query
        :return: A response if an error occurred or session information in a
            dictionary
        """

        # target_entity_id = environ["PATH_INFO"].lstrip("/").split('/')[1]
        # environ["vopaas.target_entity_id"] = target_entity_id

        target_entity_id = context.path.lstrip("/").split('/')[1]
        context.internal_data["vopaas.target_entity_id"] = target_entity_id

        # Add endpoints dynamically
        idp_conf_file = copy.deepcopy(self.config)
        idp_endpoints = []
        for endp_category in self.endpoints.keys():
            for func, endpoint in self.endpoints[endp_category].items():
                endpoint = "{base}/{provider}/{target_id}/{endpoint}".format(
                    base=self.base, provider=context.target_backend,
                    target_id=target_entity_id, endpoint=endpoint)
                idp_endpoints.append((endpoint, func))
            idp_conf_file["service"]["idp"]["endpoints"][endp_category] = idp_endpoints
        idp_config = IdPConfig().load(idp_conf_file, metadata_construction=False)

        idp = Server(config=idp_config)

        # _request = unpack(environ, binding_in)
        _request = context.request
        _binding_in = service.INV_BINDING_MAP[binding_in]

        try:
            _dict = self.verify_request(idp, _request["SAMLRequest"],
                                        _binding_in)
        except UnknownPrincipal as excp:
            LOGGER.error("UnknownPrincipal: %s", excp)
            return ServiceError("UnknownPrincipal: %s" % (excp,))
        except UnsupportedBinding as excp:
            LOGGER.error("UnsupportedBinding: %s", excp)
            return ServiceError("UnsupportedBinding: %s" % (excp,))

        _binding = _dict["resp_args"]["binding"]
        if _dict["response"]:  # An error response
            http_args = idp.apply_binding(
                _binding, "%s" % _dict["response"],
                _dict["resp_args"]["destination"],
                _request["RelayState"], response=True)

            LOGGER.debug("HTTPargs: %s", http_args)
            return response(_binding, http_args)
        else:

            idp_entityid = "%s/%s" % (self.config["entityid"], target_entity_id)
            request_state = {"origin_authn_req": _dict["authn_req"].to_string().decode("utf-8"),
                             "relay_state": _request["RelayState"],
                             "proxy_idp_entityid": idp_entityid, }

            state = urlsafe_b64encode(json.dumps(request_state).encode("UTF-8")).decode(
                "UTF-8")

            return self.auth_req_callback_func(context, _dict, state)

    def handle_authn_response(self, context, internal_response, state):
        request_state = json.loads(urlsafe_b64decode(state.encode("UTF-8")).decode("UTF-8"))
        origin_authn_req = authn_request_from_string(request_state["origin_authn_req"])

        # Change the idp entity id dynamically
        idp_config_file = copy.deepcopy(self.config)
        idp_config_file["entityid"] = request_state["proxy_idp_entityid"]
        idp_config = IdPConfig().load(idp_config_file, metadata_construction=False)

        idp = Server(config=idp_config)

        # Diverse arguments needed to construct the response
        resp_args = idp.response_args(origin_authn_req)

        # Will signed the response by default
        resp = self.construct_authn_response(idp,
                                             internal_response["ava"],
                                             name_id=internal_response["name_id"],
                                             authn=internal_response["auth_info"],
                                             resp_args=resp_args,
                                             relay_state=request_state["relay_state"],
                                             sign_response=True)

        return resp

    def construct_authn_response(self, idp, identity, name_id, authn,
                                 resp_args,
                                 relay_state, sign_response=True):
        """

        :param identity:
        :param name_id:
        :param authn:
        :param resp_args:
        :param relay_state:
        :param sign_response:
        :return:
        """

        _resp = idp.create_authn_response(identity, name_id=name_id,
                                          authn=authn,
                                          sign_response=sign_response,
                                          **resp_args)

        http_args = idp.apply_binding(
            resp_args["binding"], "%s" % _resp, resp_args["destination"],
            relay_state, response=True)

        LOGGER.debug("HTTPargs: %s", http_args)

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

    def register_endpoints(self, providers):
        """
        Given the configuration, return a set of URL to function mappings.
        """

        url_map = []

        for binding, endp in self.endpoints["single_sign_on_service"].items():
            valid_providers = ""
            for provider in providers:
                valid_providers = "{}|^{}".format(valid_providers, provider)
            valid_providers = valid_providers.lstrip("|")
            parsed_endp = urlparse(endp)
            url_map.append(("%s/[\w]+/%s$" % (valid_providers, parsed_endp.path),
                            (self.handle_authn_request, service.BINDING_MAP[binding])))
            url_map.append(("%s/[\w]+/%s/(.*)$" % (valid_providers, parsed_endp.path),
                            (self.handle_authn_request, service.BINDING_MAP[binding])))

        return url_map
