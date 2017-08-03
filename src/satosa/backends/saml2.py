"""
A saml2 backend module for the satosa proxy
"""
import copy
import functools
import json
import logging
from base64 import urlsafe_b64encode, urlsafe_b64decode
from urllib.parse import urlparse

from saml2.client_base import Base
from saml2.config import SPConfig
from saml2.extension.ui import NAMESPACE as UI_NAMESPACE
from saml2.metadata import create_metadata_string
from saml2.authn_context import requested_authn_context

import satosa.util as util
from satosa.base import SAMLBaseModule
from .base import BackendModule
from ..exception import SATOSAAuthenticationError
from ..internal_data import (InternalResponse,
                             AuthenticationInformation)
from ..logging_util import satosa_logging
from ..metadata_creation.description import (MetadataDescription, OrganizationDesc,
                                             ContactPersonDesc, UIInfoDesc)
from ..response import SeeOther, Response
from ..saml_util import make_saml_response


logger = logging.getLogger(__name__)


class SAMLBackend(BackendModule, SAMLBaseModule):
    """
    A saml2 backend module (acting as a SP).
    """
    KEY_DISCO_SRV = 'disco_srv'
    KEY_SP_CONFIG = 'sp_config'
    VALUE_ACR_COMPARISON_DEFAULT = 'exact'

    def __init__(self, outgoing, internal_attributes, config, base_url, name):
        """
        :type outgoing:
        (satosa.context.Context, satosa.internal_data.InternalResponse) -> satosa.response.Response
        :type internal_attributes: dict[str, dict[str, list[str] | str]]
        :type config: dict[str, Any]
        :type base_url: str
        :type name: str

        :param outgoing: Callback should be called by the module after
                                   the authorization in the backend is done.
        :param internal_attributes: Internal attribute map
        :param config: The module config
        :param base_url: base url of the service
        :param name: name of the plugin
        """
        super().__init__(outgoing, internal_attributes, base_url, name)
        self.config = self.init_config(config)

        sp_config = SPConfig().load(copy.deepcopy(config[self.KEY_SP_CONFIG]), False)
        self.sp = Base(sp_config)

        self.discosrv = config.get(self.KEY_DISCO_SRV)
        self.encryption_keys = []
        self.outstanding_queries = {}

        sp_keypairs = sp_config.getattr('encryption_keypairs', '')
        sp_key_file = sp_config.getattr('key_file', '')
        if sp_keypairs:
            key_file_paths = [pair['key_file'] for pair in sp_keypairs]
        elif sp_key_file:
            key_file_paths = [sp_key_file]
        else:
            key_file_paths = []

        for p in key_file_paths:
            with open(p) as key_file:
                self.encryption_keys.append(key_file.read())

    def start_auth(self, context, internal_req):
        """
        See super class method satosa.backends.base.BackendModule#start_auth
        :type context: satosa.context.Context
        :type internal_req: satosa.internal_data.InternalRequest
        :rtype: satosa.response.Response
        """

        # if there is only one IdP in the metadata, bypass the discovery service
        idps = self.sp.metadata.identity_providers()
        if len(idps) == 1 and "mdq" not in self.config["sp_config"]["metadata"]:
            return self.authn_request(context, idps[0])

        try:
            # find mirrored entity id
            entity_id = context.internal_data["mirror.target_entity_id"]
        except KeyError:
            # redirect to discovery server
            return self.disco_query()
        else:
            entity_id = urlsafe_b64decode(entity_id).decode("utf-8")
            return self.authn_request(context, entity_id)

    def disco_query(self):
        """
        Makes a request to the discovery server

        :type context: satosa.context.Context
        :type internal_req: satosa.internal_data.InternalRequest
        :rtype: satosa.response.SeeOther

        :param context: The current context
        :param internal_req: The request
        :return: Response
        """
        return_url = self.sp.config.getattr("endpoints", "sp")["discovery_response"][0][0]
        loc = self.sp.create_discovery_service_request(self.discosrv, self.sp.config.entityid, **{"return": return_url})
        return SeeOther(loc)

    def construct_requested_authn_context(self, entity_id):
        if not self.acr_mapping:
            return None

        acr_entry = util.get_dict_defaults(self.acr_mapping, entity_id)
        if not acr_entry:
            return None

        if type(acr_entry) is not dict:
            acr_entry = {
                "class_ref": acr_entry,
                "comparison": self.VALUE_ACR_COMPARISON_DEFAULT,
            }

        authn_context = requested_authn_context(
            acr_entry['class_ref'], comparison=acr_entry.get(
                'comparison', self.VALUE_ACR_COMPARISON_DEFAULT))

        return authn_context

    def authn_request(self, context, entity_id):
        """
        Do an authorization request on idp with given entity id.
        This is the start of the authorization.

        :type context: satosa.context.Context
        :type entity_id: str
        :rtype: satosa.response.Response

        :param context: The current context
        :param entity_id: Target IDP entity id
        :return: response to the user agent
        """
        kwargs = {}
        authn_context = self.construct_requested_authn_context(entity_id)
        if authn_context:
            kwargs['requested_authn_context'] = authn_context

        try:
            binding, destination = self.sp.pick_binding(
                "single_sign_on_service", None, "idpsso", entity_id=entity_id)
            satosa_logging(logger, logging.DEBUG, "binding: %s, destination: %s" % (binding, destination),
                           context.state)
            acs_endp, response_binding = self.sp.config.getattr("endpoints", "sp")["assertion_consumer_service"][0]
            req_id, req = self.sp.create_authn_request(
                destination, binding=response_binding, **kwargs)
            relay_state = util.rndstr()
            ht_args = self.sp.apply_binding(binding, "%s" % req, destination, relay_state=relay_state)
            satosa_logging(logger, logging.DEBUG, "ht_args: %s" % ht_args, context.state)
        except Exception as exc:
            satosa_logging(logger, logging.DEBUG, "Failed to construct the AuthnRequest for state", context.state,
                           exc_info=True)
            raise SATOSAAuthenticationError(context.state, "Failed to construct the AuthnRequest") from exc

        if self.sp.config.getattr('allow_unsolicited', 'sp') is False:
            if req_id in self.outstanding_queries:
                errmsg = "Request with duplicate id {}".format(req_id)
                satosa_logging(logger, logging.DEBUG, errmsg, context.state)
                raise SATOSAAuthenticationError(context.state, errmsg)
            self.outstanding_queries[req_id] = req

        context.state[self.name] = {"relay_state": relay_state}
        return make_saml_response(binding, ht_args)

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
        if not context.request["SAMLResponse"]:
            satosa_logging(logger, logging.DEBUG, "Missing Response for state", context.state)
            raise SATOSAAuthenticationError(context.state, "Missing Response")

        try:
            authn_response = self.sp.parse_authn_request_response(
                context.request["SAMLResponse"],
                binding, outstanding=self.outstanding_queries)
        except Exception as err:
            satosa_logging(logger, logging.DEBUG, "Failed to parse authn request for state", context.state,
                           exc_info=True)
            raise SATOSAAuthenticationError(context.state, "Failed to parse authn request") from err

        if self.sp.config.getattr('allow_unsolicited', 'sp') is False:
            req_id = authn_response.in_response_to
            if req_id not in self.outstanding_queries:
                errmsg = "No request with id: {}".format(req_id),
                satosa_logging(logger, logging.DEBUG, errmsg, context.state)
                raise SATOSAAuthenticationError(context.state, errmsg)
            del self.outstanding_queries[req_id]

        # check if the relay_state matches the cookie state
        if context.state[self.name]["relay_state"] != context.request["RelayState"]:
            satosa_logging(logger, logging.DEBUG,
                           "State did not match relay state for state", context.state)
            raise SATOSAAuthenticationError(context.state, "State did not match relay state")

        del context.state[self.name]
        return self.auth_callback_func(context, self._translate_response(authn_response, context.state))

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
            entity_id = info["entityID"]
        except KeyError as err:
            satosa_logging(logger, logging.DEBUG, "No IDP chosen for state", state, exc_info=True)
            raise SATOSAAuthenticationError(state, "No IDP chosen") from err

        return self.authn_request(context, entity_id)

    def _translate_response(self, response, state):
        """
        Translates a saml authorization response to an internal response

        :type response: saml2.response.AuthnResponse
        :rtype: satosa.internal_data.InternalResponse
        :param response: The saml authorization response
        :return: A translated internal response
        """

        # The response may have been encrypted by the IdP so if we have an encryption key, try it
        if self.encryption_keys:
            response.parse_assertion(self.encryption_keys)

        authn_info = response.authn_info()[0]
        auth_class_ref = authn_info[0]
        timestamp = response.assertion.authn_statement[0].authn_instant
        issuer = response.response.issuer.text

        auth_info = AuthenticationInformation(auth_class_ref, timestamp, issuer)
        internal_resp = SAMLInternalResponse(auth_info=auth_info)

        internal_resp.user_id = response.get_subject().text
        internal_resp.attributes = self.converter.to_internal(self.attribute_profile, response.ava)

        # The SAML response may not include a NameID
        try:
            internal_resp.name_id = response.assertion.subject.name_id
        except AttributeError:
            pass

        satosa_logging(logger, logging.DEBUG, "received attributes:\n%s" % json.dumps(response.ava, indent=4), state)
        return internal_resp

    def _metadata_endpoint(self, context):
        """
        Endpoint for retrieving the backend metadata
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The current context
        :return: response with metadata
        """
        satosa_logging(logger, logging.DEBUG, "Sending metadata response", context.state)

        metadata_string = create_metadata_string(None, self.sp.config, 4, None, None, None, None,
                                                 None).decode("utf-8")
        return Response(metadata_string, content="text/xml")

    def register_endpoints(self):
        """
        See super class method satosa.backends.base.BackendModule#register_endpoints
        :rtype list[(str, ((satosa.context.Context, Any) -> Any, Any))]
        """
        url_map = []
        sp_endpoints = self.sp.config.getattr("endpoints", "sp")
        for endp, binding in sp_endpoints["assertion_consumer_service"]:
            parsed_endp = urlparse(endp)
            url_map.append(("^%s$" % parsed_endp.path[1:], functools.partial(self.authn_response, binding=binding)))

        if self.discosrv:
            for endp, binding in sp_endpoints["discovery_response"]:
                parsed_endp = urlparse(endp)
                url_map.append(
                    ("^%s$" % parsed_endp.path[1:], self.disco_response))

        if self.expose_entityid_endpoint():
            parsed_entity_id = urlparse(self.sp.config.entityid)
            url_map.append(("^{0}".format(parsed_entity_id.path[1:]),
                            self._metadata_endpoint))

        return url_map

    def get_metadata_desc(self):
        """
        See super class satosa.backends.backend_base.BackendModule#get_metadata_desc
        :rtype: satosa.metadata_creation.description.MetadataDescription
        """
        entity_descriptions = []

        idp_entities = self.sp.metadata.with_descriptor("idpsso")
        for entity_id, entity in idp_entities.items():
            description = MetadataDescription(urlsafe_b64encode(entity_id.encode("utf-8")).decode("utf-8"))

            # Add organization info
            try:
                organization_info = entity["organization"]
            except KeyError:
                pass
            else:
                organization = OrganizationDesc()
                for name_info in organization_info.get("organization_name", []):
                    organization.add_name(name_info["text"], name_info["lang"])
                for display_name_info in organization_info.get("organization_display_name", []):
                    organization.add_display_name(display_name_info["text"], display_name_info["lang"])
                for url_info in organization_info.get("organization_url", []):
                    organization.add_url(url_info["text"], url_info["lang"])
                description.organization = organization

            # Add contact person info
            try:
                contact_persons = entity["contact_person"]
            except KeyError:
                pass
            else:
                for person in contact_persons:
                    person_desc = ContactPersonDesc()
                    person_desc.contact_type = person.get("contact_type")
                    for address in person.get('email_address', []):
                        person_desc.add_email_address(address["text"])
                    if "given_name" in person:
                        person_desc.given_name = person["given_name"]["text"]
                    if "sur_name" in person:
                        person_desc.sur_name = person["sur_name"]["text"]

                    description.add_contact_person(person_desc)

            # Add UI info
            ui_info = self.sp.metadata.extension(entity_id, "idpsso_descriptor", "{}&UIInfo".format(UI_NAMESPACE))
            if ui_info:
                ui_info = ui_info[0]
                ui_info_desc = UIInfoDesc()
                for desc in ui_info.get("description", []):
                    ui_info_desc.add_description(desc["text"], desc["lang"])
                for name in ui_info.get("display_name", []):
                    ui_info_desc.add_display_name(name["text"], name["lang"])
                for logo in ui_info.get("logo", []):
                    ui_info_desc.add_logo(logo["text"], logo["width"], logo["height"], logo.get("lang"))
                description.ui_info = ui_info_desc

            entity_descriptions.append(description)
        return entity_descriptions

class SAMLInternalResponse(InternalResponse):
    """
    Like the parent InternalResponse, holds internal representation of
    service related data, but includes additional details relevant to
    SAML interoperability.

    :type name_id: instance of saml2.saml.NameID from pysaml2
    """
    def __init__(self, auth_info=None):
        super().__init__(auth_info)

        self.name_id = None

    def to_dict(self):
        """
        Converts a SAMLInternalResponse object to a dict
        :rtype: dict[str, dict[str, str] | str]
        :return: A dict representation of the object
        """
        _dict = super().to_dict()

        if self.name_id:
            _dict['name_id'] = {self.name_id.format : self.name_id.text}
        else:
            _dict['name_id'] = None

        return _dict

