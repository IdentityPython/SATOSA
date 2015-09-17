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
from saml2.extension.ui import NAMESPACE as UI_NAMESPACE

from vopaas_proxy.service import BINDING_MAP, response
import vopaas_proxy.service as service

logger = logging.getLogger(__name__)


class SamlSP(BackendBase):
    def __init__(self, outgoing, config, discosrv=None, bindings=None):
        super(SamlSP, self).__init__(outgoing)
        sp_config = SPConfig().load(copy.deepcopy(config), False)

        self.sp = Base(sp_config)
        self.idp_disco_query_param = "entityID"
        self.discosrv = discosrv
        if bindings:
            self.bindings = bindings
        else:
            self.bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
        logger.debug("--- SSO ---")

    def start_auth(self, context, request_info, state):
        _cli = self.sp
        req_args = request_info["req_args"]
        entity_id = context.internal_data["vopaas.target_entity_id"]
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
                                         relay_state=state)
            logger.debug("ht_args: %s" % ht_args)
        except Exception as exc:
            logger.exception(exc)
            return ServiceError("Failed to construct the AuthnRequest: %s" % exc)

        return response(_binding, ht_args)

    def authn_response(self, context, binding):
        """
        :param binding: Which binding the query came in over
        :returns: Error response or a response constructed by the transfer
            function
        """

        # _authn_response = unpack(environ, binding)
        _authn_response = context.request

        if not _authn_response["SAMLResponse"]:
            logger.info("Missing Response")
            return Unauthorized('Unknown user')

        binding = service.INV_BINDING_MAP[binding]
        try:
            _response = self.sp.parse_authn_request_response(
                _authn_response["SAMLResponse"], binding)
        except UnknownPrincipal as excp:
            logger.error("UnknownPrincipal: %s" % (excp,))
            return ServiceError("UnknownPrincipal: %s" % (excp,))
        except UnsupportedBinding as excp:
            logger.error("UnsupportedBinding: %s" % (excp,))
            return ServiceError("UnsupportedBinding: %s" % (excp,))
        except VerificationError as err:
            return ServiceError("Verification error: %s" % (err,))
        except Exception as err:
            return ServiceError("Other error: %s" % (err,))

        return self.auth_callback_func(context,
                                       self._translate_response(_response),
                                       _authn_response['RelayState'])

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
            entity_id = metadata_file.entity_descr.entity_id
            entity = metadata_file.entity
            desc["entityid"] = b64encode(entity_id.encode("utf-8")).decode("utf-8")

            # Add organization info
            try:
                organization = entity[entity_id]['organization']
                desc['organization'] = {}
                organization_params = [('display_name', 'organization_display_name'),
                                       ('name', 'organization_name'), ('url', 'organization_url')]
                for config_param, param in organization_params:
                    try:
                        value = []
                        for obj in organization[param]:
                            value.append((obj["text"], obj["lang"]))
                        desc['organization'][config_param] = value
                    except KeyError:
                        pass
            except:
                pass

            # Add contact person info
            try:
                contact_persons = entity[entity_id]['contact_person']
                desc['contact_person'] = []
                for cont_pers in contact_persons:
                    person = {}
                    try:
                        person['contact_type'] = cont_pers['contact_type']
                    except KeyError:
                        pass
                    try:
                        email_address = cont_pers['email_address']
                        person['email_address'] = []
                        for address in email_address:
                            person['email_address'].append(address['text'])
                    except KeyError:
                        pass
                    try:
                        person['given_name'] = cont_pers['given_name']['text']
                    except KeyError:
                        pass
                    try:
                        person['sur_name'] = cont_pers['sur_name']['text']
                    except KeyError:
                        pass
                    desc['contact_person'].append(person)
            except KeyError:
                pass

            # Add ui info
            try:
                for idpsso_desc in entity[entity_id]["idpsso_descriptor"]:
                    ui_elements = idpsso_desc["extensions"]["extension_elements"]
                    params = ["description", "display_name"]
                    ui_info = {}

                    for element in ui_elements:
                        if not element["__class__"] == "%s&UIInfo" % UI_NAMESPACE:
                            continue
                        for param in params:
                            try:
                                value = []
                                for data in element[param]:
                                    value.append({"text": data["text"], "lang": data["lang"]})
                                ui_info[param] = value
                            except KeyError:
                                pass
                        try:
                            logos = []
                            for logo in element["logo"]:
                                logos.append({"text": logo["text"], "width": logo["width"],
                                              "height": logo["height"], "lang": logo["lang"]})
                            ui_info["logo"] = logos
                        except KeyError:
                            pass
                    if ui_info:
                        desc["service"] = {"idp": {"ui_info": ui_info}}
            except KeyError:
                pass

            metadata_desc.append(desc)
        return metadata_desc
