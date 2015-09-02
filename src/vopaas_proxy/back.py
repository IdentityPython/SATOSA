#!/usr/bin/env python
import logging
import time
from urllib.parse import urlparse

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.client_base import Base
from saml2.httputil import geturl
from saml2.httputil import ServiceError
from saml2.httputil import SeeOther
from saml2.httputil import Unauthorized
from saml2.response import VerificationError
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding

from vopaas_proxy.service import BINDING_MAP
import vopaas_proxy.service as service


logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Authentication request constructor
# -----------------------------------------------------------------------------


class SamlSP(service.Service):
    def __init__(self, environ, start_response, config, cache=None,
                 outgoing=None, discosrv=None, bindings=None):
        service.Service.__init__(self, environ, start_response)
        self.sp = Base(config, state_cache=cache)
        self.environ = environ
        self.start_response = start_response
        self.cache = cache
        self.idp_disco_query_param = "entityID"
        self.outgoing = outgoing
        self.discosrv = discosrv
        if bindings:
            self.bindings = bindings
        else:
            self.bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
        logger.debug("--- SSO ---")

    def disco_response(self, *args):
        """
        If I got a useful response from the discovery server, continue with
        the authentication request.

        :return: redirect containing the authentication request
        """
        info = self.unpack_redirect()

        try:
            entity_id = info[self.idp_disco_query_param]
        except KeyError:
            resp = Unauthorized("You must chose an IdP")
            return resp(self.environ, self.start_response)
        else:
            # should I check the state variable ?
            return self.authn_request(entity_id, info["state"])

    def store_state(self, authn_req, relay_state, req_args):
        # Which page was accessed to get here
        came_from = geturl(self.environ)
        key = str(hash(came_from + self.environ["REMOTE_ADDR"] + str(time.time())))
        logger.debug("[sp.challenge] RelayState >> '%s'" % came_from)
        self.cache[key] = (authn_req, relay_state, req_args)
        return key

    def disco_query(self, authn_req, relay_state, req_args):
        """
        This service is expected to always use a discovery service. This is
        where the response is handled

        :param authn_req: The Authentication Request
        :return: A 302 messages redirecting to the discovery service
        """

        state_key = self.store_state(authn_req, relay_state, req_args)

        _cli = self.sp

        eid = _cli.config.entityid
        # returns list of 2-tuples
        dr = _cli.config.getattr("endpoints", "sp")["discovery_response"]
        # The first value of the first tuple is the one I want
        ret = dr[0][0]
        # append it to the disco server URL
        ret += "?state=%s" % state_key
        loc = _cli.create_discovery_service_request(self.discosrv, eid,
                                                    **{"return": ret})

        resp = SeeOther(loc)
        return resp(self.environ, self.start_response)

    def authn_request(self, entity_id, state_key):
        _cli = self.sp
        req_args = self.cache[state_key][2]

        try:
            # Picks a binding to use for sending the Request to the IDP
            _binding, destination = _cli.pick_binding(
                "single_sign_on_service", self.bindings, "idpsso",
                entity_id=entity_id)
            logger.debug("binding: %s, destination: %s" % (_binding,
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
                                         relay_state=state_key)
            _sid = req_id
            logger.debug("ht_args: %s" % ht_args)
        except Exception as exc:
            logger.exception(exc)
            resp = ServiceError(
                "Failed to construct the AuthnRequest: %s" % exc)
            return resp(self.environ, self.start_response)

        # remember the request
        self.cache[_sid] = state_key
        resp = self.response(_binding, ht_args, do_not_start_response=True)
        return resp(self.environ, self.start_response)

    def authn_response(self, binding):
        """
        :param binding: Which binding the query came in over
        :returns: Error response or a response constructed by the transfer
            function
        """

        _authn_response = self.unpack(binding)

        if not _authn_response["SAMLResponse"]:
            logger.info("Missing Response")
            resp = Unauthorized('Unknown user')
            return resp(self.environ, self.start_response)

        binding = service.INV_BINDING_MAP[binding]
        try:
            _response = self.sp.parse_authn_request_response(
                _authn_response["SAMLResponse"], binding,
                self.cache)
        except UnknownPrincipal as excp:
            logger.error("UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except UnsupportedBinding as excp:
            logger.error("UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except VerificationError as err:
            resp = ServiceError("Verification error: %s" % (err,))
            return resp(self.environ, self.start_response)
        except Exception as err:
            resp = ServiceError("Other error: %s" % (err,))
            return resp(self.environ, self.start_response)

        return self.outgoing(_response, self)

    def register_endpoints(self):
        """
        Given the configuration, return a set of URL to function mappings.
        """

        url_map = []
        sp_endpoints = self.sp.config.getattr("endpoints", "sp")
        for endp, binding in sp_endpoints["assertion_consumer_service"]:
            p = urlparse(endp)
            url_map.append(("^%s?(.*)$" % p.path[1:], ("SP", "authn_response",
                                                       BINDING_MAP[binding])))
            url_map.append(("^%s$" % p.path[1:], ("SP", "authn_response",
                                                  BINDING_MAP[binding])))

        if self.discosrv:
            for endp, binding in sp_endpoints["discovery_response"]:
                p = urlparse(endp)
                url_map.append(("^%s$" % p.path[1:], ("SP", "disco_response",
                                                            BINDING_MAP[binding])))

        return url_map


if __name__ == "__main__":
    import sys
    from saml2.config import config_factory

    _config = config_factory("sp", sys.argv[1])
    sp = SamlSP(None, None, _config)
    maps = sp.register_endpoints()
    print(maps)