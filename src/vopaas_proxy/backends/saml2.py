#!/usr/bin/env python
from base64 import b64encode, b64decode
import copy
import logging
from urllib.parse import urlparse

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.client_base import Base
from saml2.httputil import ServiceError
from saml2.config import SPConfig
from saml2.httputil import Unauthorized
from saml2.response import VerificationError
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from vopaas_proxy import VALID_ATTRIBUTES
from vopaas_proxy.backends.base import BackendBase

from vopaas_proxy.service import BINDING_MAP, unpack, response
import vopaas_proxy.service as service

logger = logging.getLogger(__name__)


class SamlSP(BackendBase):
    def __init__(self, outgoing, config, discosrv=None, bindings=None):
        super(SamlSP, self).__init__(outgoing)
        self.cache = {}

        sp_config = SPConfig().load(copy.deepcopy(config), False)

        self.sp = Base(sp_config, state_cache=self.cache)
        self.idp_disco_query_param = "entityID"
        self.outgoing = outgoing
        self.discosrv = discosrv
        if bindings:
            self.bindings = bindings
        else:
            self.bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
        logger.debug("--- SSO ---")

    def start_auth(self, environ, start_response, request_info, state_key, entity_id):
        _cli = self.sp
        req_args = request_info["req_args"]
        entity_id = b64decode(entity_id).decode("utf-8")
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
            return resp(environ, start_response)

        # remember the request
        self.cache[_sid] = state_key
        resp = response(environ, start_response, _binding, ht_args, do_not_start_response=True)
        return resp(environ, start_response)

    def authn_response(self, environ, start_response, binding):
        """
        :param binding: Which binding the query came in over
        :returns: Error response or a response constructed by the transfer
            function
        """

        _authn_response = unpack(environ, binding)

        if not _authn_response["SAMLResponse"]:
            logger.info("Missing Response")
            resp = Unauthorized('Unknown user')
            return resp(environ, start_response)

        binding = service.INV_BINDING_MAP[binding]
        try:
            _response = self.sp.parse_authn_request_response(
                _authn_response["SAMLResponse"], binding,
                self.cache)
        except UnknownPrincipal as excp:
            logger.error("UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(environ, start_response)
        except UnsupportedBinding as excp:
            logger.error("UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(environ, start_response)
        except VerificationError as err:
            resp = ServiceError("Verification error: %s" % (err,))
            return resp(environ, start_response)
        except Exception as err:
            resp = ServiceError("Other error: %s" % (err,))
            return resp(environ, start_response)

        return self.outgoing(environ, start_response, self._translate_response(_response),
                             self.cache[_response.in_response_to])

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

    def register_endpoints(self):
        """
        Given the configuration, return a set of URL to function mappings.
        """

        url_map = []
        sp_endpoints = self.sp.config.getattr("endpoints", "sp")
        for endp, binding in sp_endpoints["assertion_consumer_service"]:
            p = urlparse(endp)
            url_map.append(("^%s?(.*)$" % p.path[1:], (self.authn_response,
                                                       BINDING_MAP[binding])))
            url_map.append(("^%s$" % p.path[1:], (self.authn_response,
                                                  BINDING_MAP[binding])))

        if self.discosrv:
            for endp, binding in sp_endpoints["discovery_response"]:
                p = urlparse(endp)
                url_map.append(("^%s$" % p.path[1:], (self.disco_response,
                                                      BINDING_MAP[binding])))

        return url_map

    def get_metadata_desc(self):
        # TODO Only get IDPs
        metadata_desc = []
        for metadata_file in self.sp.metadata.metadata:
            desc = {}
            metadata_file = self.sp.metadata.metadata[metadata_file]
            entity_id = b64encode(metadata_file.entity_descr.entity_id.encode("utf-8")).decode(
                "utf-8")
            # entity = metadata_file.entity
            desc["entity_id"] = entity_id
            metadata_desc.append(desc)
            # organization = entity[entity_id]['organization']
            # metadata_desc[entity_id]['organization']['organization_display_name'] =
            # organization['organization_display_name']['text']
            # metadata_desc[entity_id]['organization']['organization_name'] =
            # organization['organization_name']['text']
            # metadata_desc[entity_id]['organization']['organization_name'] =
            # organization['organization_name']['text']
        return metadata_desc
