#!/usr/bin/env python
import logging
from urllib.parse import urlparse

from saml2.httputil import ServiceError
from saml2.httputil import Response
from saml2.httputil import Redirect
from saml2.httputil import Unauthorized
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.server import Server

import vopaas_proxy.service as service
from vopaas_proxy.service import unpack, response

logger = logging.getLogger(__name__)


class SamlIDP():
    def __init__(self, environ, start_response, conf, cache, incoming):
        """
        Constructor for the class.
        :param environ: WSGI environ
        :param start_response: WSGI start response function
        :param conf: The SAML configuration
        :param cache: Cache with active sessions
        """
        self.environ = environ
        self.start_response = start_response
        self.response_bindings = None
        self.idp = Server(config=conf, cache=cache)
        self.incoming = incoming

    def verify_request(self, query, binding):
        """ Parses and verifies the SAML Authentication Request

        :param query: The SAML authn request, transport encoded
        :param binding: Which binding the query came in over
        :returns: dictionary
        """

        if not query:
            logger.info("Missing QUERY")
            resp = Unauthorized('Unknown user')
            return {"response": resp(self.environ, self.start_response)}

        req_info = self.idp.parse_authn_request(query, binding)

        logger.info("parsed OK")
        _authn_req = req_info.message
        logger.debug("%s" % _authn_req)

        # Check that I know where to send the reply to
        try:
            binding_out, destination = self.idp.pick_binding(
                "assertion_consumer_service",
                bindings=self.response_bindings,
                entity_id=_authn_req.issuer.text, request=_authn_req)
        except Exception as err:
            logger.error("Couldn't find receiver endpoint: %s" % err)
            raise

        logger.debug("Binding: %s, destination: %s" % (binding_out,
                                                       destination))

        resp_args = {}
        try:
            resp_args = self.idp.response_args(_authn_req)
            _resp = None
        except UnknownPrincipal as excp:
            _resp = self.idp.create_error_response(_authn_req.id,
                                                   destination, excp)
        except UnsupportedBinding as excp:
            _resp = self.idp.create_error_response(_authn_req.id,
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

    def handle_authn_request(self, binding_in):
        """
        Deal with an authentication request

        :param binding_in: Which binding was used when receiving the query
        :return: A response if an error occurred or session information in a
            dictionary
        """

        _request = unpack(self.environ, binding_in)
        _binding_in = service.INV_BINDING_MAP[binding_in]

        try:
            _dict = self.verify_request(_request["SAMLRequest"], _binding_in)
        except UnknownPrincipal as excp:
            logger.error("UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except UnsupportedBinding as excp:
            logger.error("UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(self.environ, self.start_response)

        _binding = _dict["resp_args"]["binding"]
        if _dict["response"]:  # An error response
            http_args = self.idp.apply_binding(
                _binding, "%s" % _dict["response"],
                _dict["resp_args"]["destination"],
                _request["RelayState"], response=True)

            logger.debug("HTTPargs: %s" % http_args)
            return response(self.environ, self.start_response, _binding, http_args)
        else:
            return self.incoming(_dict, self.environ, self.start_response,
                                 _request["RelayState"])

    def construct_authn_response(self, identity, name_id, authn, resp_args,
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

        _resp = self.idp.create_authn_response(identity, name_id=name_id,
                                               authn=authn,
                                               sign_response=sign_response,
                                               **resp_args)

        http_args = self.idp.apply_binding(
            resp_args["binding"], "%s" % _resp, resp_args["destination"],
            relay_state, response=True)

        logger.debug("HTTPargs: %s" % http_args)

        resp = None
        if http_args["data"]:
            resp = Response(http_args["data"], headers=http_args["headers"])
        else:
            for header in http_args["headers"]:
                if header[0] == "Location":
                    resp = Redirect(header[1])

        if not resp:
            resp = ServiceError("Don't know how to return response")

        return resp(self.environ, self.start_response)

    def register_endpoints(self, conf):
        """
        Given the configuration, return a set of URL to function mappings.
        """

        url_map = []
        # idp_endpoints = self.idp.config.getattr("endpoints", "idp")
        # idp_endpoints = conf.SINGLE_SIGN_ON_SERVICE
        idp_endpoints = conf.ENDPOINTS
        providers = list(conf.CONFIG["backends"].keys())

        for binding, endp in idp_endpoints["single_sign_on_service"].items():
            valid_providers = ""
            for provider in providers:
                valid_providers = "{}|^{}".format(valid_providers, provider)
            valid_providers = valid_providers.lstrip("|")
            p = urlparse(endp)
            url_map.append(("%s/[\w]+/%s$" % (valid_providers, p.path),
                            ("IDP", "handle_authn_request",
                             service.BINDING_MAP[binding])))
            url_map.append(("%s/[\w]+/%s/(.*)$" % (valid_providers, p.path),
                            ("IDP", "handle_authn_request",
                             service.BINDING_MAP[binding])))

        return url_map
