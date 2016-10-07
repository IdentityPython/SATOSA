"""
A pysaml2 frontend module for the satosa proxy
"""
import copy
import functools
import json
import logging
from urllib.parse import urlparse

from saml2 import SAMLError
from saml2.config import IdPConfig
from saml2.extension.ui import NAMESPACE as UI_NAMESPACE
from saml2.metadata import create_metadata_string
from saml2.saml import NameID, NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT
from saml2.samlp import name_id_policy_from_string
from saml2.server import Server

from .base import FrontendModule
from ..internal_data import InternalRequest, UserIdHashType
from ..logging_util import satosa_logging
from ..response import Response
from ..response import ServiceError
from ..saml_util import make_saml_response

logger = logging.getLogger(__name__)


def saml_name_id_format_to_hash_type(name_format):
    """
    Translate pySAML2 name format to satosa format

    :type name_format: str
    :rtype: satosa.internal_data.UserIdHashType
    :param name_format: SAML2 name format
    :return: satosa format
    """
    if name_format == NAMEID_FORMAT_PERSISTENT:
        return UserIdHashType.persistent

    return UserIdHashType.transient


def hash_type_to_saml_name_id_format(hash_type):
    """
    Translate satosa format to pySAML2 name format

    :type hash_type: satosa.internal_data.UserIdHashType
    :rtype: str
    :param hash_type: satosa format
    :return: pySAML2 name format
    """
    if hash_type == UserIdHashType.transient.name:
        return NAMEID_FORMAT_TRANSIENT
    elif hash_type == UserIdHashType.persistent.name:
        return NAMEID_FORMAT_PERSISTENT
    return NAMEID_FORMAT_PERSISTENT


class SAMLFrontend(FrontendModule):
    """
    A pysaml2 frontend module
    """

    def __init__(self, auth_req_callback_func, internal_attributes, conf, base_url, name):
        self._validate_config(conf)

        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)
        self.config = conf
        self.endpoints = conf["endpoints"]
        self.acr_mapping = conf.get("acr_mapping")
        self.custom_attribute_release = conf.get("custom_attribute_release")
        self.attribute_profile = conf.get("attribute_profile", "saml")
        self.idp = None

    def handle_authn_response(self, context, internal_response):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :rtype satosa.response.Response
        """
        return self._handle_authn_response(context, internal_response, self.idp)

    def handle_authn_request(self, context, binding_in):
        """
        This method is bound to the starting endpoint of the authentication.

        :type context: satosa.context.Context
        :type binding_in: str
        :rtype: satosa.response.Response

        :param context: The current context
        :param binding_in: The binding type (http post, http redirect, ...)
        :return: response
        """
        return self._handle_authn_request(context, binding_in, self.idp)

    def handle_backend_error(self, exception):
        """
        See super class satosa.frontends.base.FrontendModule
        :type exception: satosa.exception.SATOSAError
        :rtype: satosa.response.Response
        """
        return self._handle_backend_error(exception, self.idp)

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        """
        self.idp_config = self._build_idp_config_endpoints(self.config["idp_config"], backend_names)
        # Create the idp
        idp_config = IdPConfig().load(copy.deepcopy(self.idp_config), metadata_construction=False)
        self.idp = Server(config=idp_config)
        return self._register_endpoints(backend_names)

    def _create_state_data(self, context, resp_args, relay_state):
        """
        Returns a dict containing the state needed in the response flow.

        :type context: satosa.context.Context
        :type resp_args: dict[str, str | saml2.samlp.NameIDPolicy]
        :type relay_state: str
        :rtype: dict[str, dict[str, str] | str]

        :param context: The current context
        :param resp_args: Response arguments
        :param relay_state: Request relay state
        :return: A state as a dict
        """
        if "name_id_policy" in resp_args and resp_args["name_id_policy"] is not None:
            resp_args["name_id_policy"] = resp_args["name_id_policy"].to_string().decode("utf-8")
        return {"resp_args": resp_args, "relay_state": relay_state}

    def load_state(self, state):
        """
        Loads a state from state
        :type state: satosa.state.State
        :rtype: dict[str, Any]
        :param state: The current state
        :return: The dictionary given by the save_state function
        """
        state_data = state[self.name]
        if isinstance(state_data["resp_args"]["name_id_policy"], str):
            state_data["resp_args"]["name_id_policy"] = name_id_policy_from_string(
                state_data["resp_args"]["name_id_policy"])
        return state_data

    def _validate_config(self, config):
        """
        Validates some parts of the module config
        :type config: dict[str, dict[str, Any] | str]
        :param config: The module config
        """
        if not config:
            raise ValueError("conf can't be 'None'")

        for key in {"idp_config", "endpoints"}:
            if key not in config:
                raise ValueError("Missing key '%s' in config" % key)

    def _handle_authn_request(self, context, binding_in, idp):
        """
        See doc for handle_authn_request method.

        :type context: satosa.context.Context
        :type binding_in: str
        :type idp: saml.server.Server
        :rtype: satosa.response.Response

        :param context: The current context
        :param binding_in: The pysaml binding type
        :param idp: The saml frontend idp server
        :return: response
        """
        req_info = idp.parse_authn_request(context.request["SAMLRequest"], binding_in)
        authn_req = req_info.message
        satosa_logging(logger, logging.DEBUG, "%s" % authn_req, context.state)

        try:
            resp_args = idp.response_args(authn_req)
        except SAMLError as e:
            satosa_logging(logger, logging.ERROR, "Could not find necessary info about entity: %s" % e, context.state)
            return ServiceError("Incorrect request from requester: %s" % e)

        context.state[self.name] = self._create_state_data(context, idp.response_args(authn_req),
                                                           context.request.get("RelayState"))

        if authn_req.name_id_policy:
            name_format = saml_name_id_format_to_hash_type(authn_req.name_id_policy.format)
        else:
            # default to name id format from metadata, or just transient name id
            name_format_from_metadata = idp.metadata[resp_args["sp_entity_id"]]["spsso_descriptor"][0].get(
                "name_id_format")
            if name_format_from_metadata:
                name_format = saml_name_id_format_to_hash_type(name_format_from_metadata[0]["text"])
            else:
                name_format = UserIdHashType.transient

        requester_name = self._get_sp_display_name(idp, resp_args["sp_entity_id"])
        internal_req = InternalRequest(name_format, resp_args["sp_entity_id"], requester_name)

        idp_policy = idp.config.getattr("policy", "idp")
        if idp_policy:
            approved_attributes = self._get_approved_attributes(idp, idp_policy, internal_req.requester, context.state)
            internal_req.approved_attributes = approved_attributes

        return self.auth_req_callback_func(context, internal_req)

    def _get_approved_attributes(self, idp, idp_policy, sp_entity_id, state):
        """
        Returns a list of approved attributes

        :type idp: saml.server.Server
        :type idp_policy: saml2.assertion.Policy
        :type sp_entity_id: str
        :type state: satosa.state.State
        :rtype: list[str]

        :param idp: The saml frontend idp server
        :param idp_policy: The idp policy
        :param sp_entity_id: The requesting sp entity id
        :param state: The current state
        :return: A list containing approved attributes
        """
        name_format = idp_policy.get_name_form(sp_entity_id)
        attrconvs = idp.config.attribute_converters
        idp_policy.acs = attrconvs
        attribute_filter = []
        for aconv in attrconvs:
            if aconv.name_format == name_format:
                all_attributes = {v: None for v in aconv._fro.values()}
                attribute_filter = list(idp_policy.restrict(all_attributes, sp_entity_id, idp.metadata).keys())
                break
        attribute_filter = self.converter.to_internal_filter(self.attribute_profile, attribute_filter)
        satosa_logging(logger, logging.DEBUG, "Filter: %s" % attribute_filter, state)
        return attribute_filter

    def _filter_attributes(self, idp, internal_response, context,):
        idp_policy = idp.config.getattr("policy", "idp")
        if idp_policy:
            approved_attributes = self._get_approved_attributes(idp, idp_policy, internal_response.requester,
                                                                context.state)
            attributes = {k: v for k, v in internal_response.attributes.items() if k in approved_attributes}

        return attributes

    def _handle_authn_response(self, context, internal_response, idp):
        """
        See super class satosa.frontends.base.FrontendModule

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :type idp: saml.server.Server

        :param context: The current context
        :param internal_response: The internal response
        :param idp: The saml frontend idp server
        :return: A saml response
        """
        request_state = self.load_state(context.state)

        resp_args = request_state["resp_args"]
        internal_response.attributes = self._filter_attributes(idp, internal_response, context)
        ava = self.converter.from_internal(self.attribute_profile, internal_response.attributes)

        auth_info = {}
        if self.acr_mapping:
            auth_info["class_ref"] = self.acr_mapping.get(internal_response.auth_info.issuer, self.acr_mapping[""])
        else:
            auth_info["class_ref"] = internal_response.auth_info.auth_class_ref

        if self.custom_attribute_release:
            custom_release_per_idp = self.custom_attribute_release.get(internal_response.auth_info.issuer, {})
            custom_release = custom_release_per_idp.get(resp_args["sp_entity_id"], {})
            attributes_to_remove = custom_release.get("exclude", [])
            for k in attributes_to_remove:
                ava.pop(k, None)

        name_id = NameID(text=internal_response.user_id,
                         format=hash_type_to_saml_name_id_format(internal_response.user_id_hash_type),
                         sp_name_qualifier=None,
                         name_qualifier=None)

        satosa_logging(logger, logging.DEBUG, "returning attributes %s" % json.dumps(ava), context.state)
        resp = idp.create_authn_response(ava, name_id=name_id, authn=auth_info, sign_response=True, **resp_args)
        http_args = idp.apply_binding(resp_args["binding"], str(resp), resp_args["destination"],
                                      request_state["relay_state"], response=True)
        del context.state[self.name]
        return make_saml_response(resp_args["binding"], http_args)

    def _handle_backend_error(self, exception, idp):
        """
        See super class satosa.frontends.base.FrontendModule

        :type exception: satosa.exception.SATOSAAuthenticationError
        :type idp: saml.server.Server
        :rtype: satosa.response.Response

        :param exception: The SATOSAAuthenticationError
        :param idp: The saml frontend idp server
        :return: A response
        """
        loaded_state = self.load_state(exception.state)
        relay_state = loaded_state["relay_state"]
        resp_args = loaded_state["resp_args"]
        error_resp = idp.create_error_response(resp_args["in_response_to"],
                                               resp_args["destination"],
                                               Exception(exception.message))
        http_args = idp.apply_binding(resp_args["binding"], str(error_resp), resp_args["destination"], relay_state,
                                      response=True)

        satosa_logging(logger, logging.DEBUG, "HTTPargs: %s" % http_args, exception.state)
        return make_saml_response(resp_args["binding"], http_args)

    def _metadata_endpoint(self, context):
        """
        Endpoint for retrieving the backend metadata
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The current context
        :return: response with metadata
        """
        satosa_logging(logger, logging.DEBUG, "Sending metadata response", context.state)
        metadata_string = create_metadata_string(None, self.idp.config, 4, None, None, None, None,
                                                 None).decode("utf-8")
        return Response(metadata_string, content="text/xml")

    def _register_endpoints(self, providers):
        """
        Register methods to endpoints
        :type providers: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :param providers: A list of backend providers
        :return: A list of endpoint/method pairs
        """
        url_map = []

        for endp_category in self.endpoints:
            for binding, endp in self.endpoints[endp_category].items():
                valid_providers = ""
                for provider in providers:
                    valid_providers = "{}|^{}".format(valid_providers, provider)
                valid_providers = valid_providers.lstrip("|")
                parsed_endp = urlparse(endp)
                url_map.append(("(%s)/%s$" % (valid_providers, parsed_endp.path),
                                functools.partial(self.handle_authn_request, binding_in=binding)))

        return url_map

    def _build_idp_config_endpoints(self, config, providers):
        """
        Builds the final frontend module config

        :type config: dict[str, Any]
        :type providers: list[str]
        :rtype: dict[str, Any]

        :param config: The module config
        :param providers: A list of backend names
        :return: The final config
        """
        # Add an endpoint to each provider
        idp_endpoints = []
        for endp_category in self.endpoints:
            for func, endpoint in self.endpoints[endp_category].items():
                for provider in providers:
                    _endpoint = "{base}/{provider}/{endpoint}".format(
                        base=self.base_url, provider=provider, endpoint=endpoint)
                    idp_endpoints.append((_endpoint, func))
            config["service"]["idp"]["endpoints"][endp_category] = idp_endpoints

        return config

    def _get_sp_display_name(self, idp, entity_id):
        extensions = idp.metadata.extension(entity_id, "spsso_descriptor", "{}&UIInfo".format(UI_NAMESPACE))
        if not extensions:
            return None

        try:
            return extensions[0]["display_name"]
        except (IndexError, KeyError) as e:
            pass

        return None


class SAMLMirrorFrontend(SAMLFrontend):
    """
    Frontend module that uses dynamic entity id and partially dynamic endpoints.
    """

    def _load_endpoints_to_config(self, provider, target_entity_id, config=None):
        """
        Loads approved endpoints to the config.

        :type url_base: str
        :type provider: str
        :type target_entity_id: str
        :rtype: dict[str, Any]

        :param url_base: The proxy base url
        :param provider: target backend name
        :param target_entity_id: frontend target entity id
        :return: IDP config with endpoints
        """
        idp_conf = copy.deepcopy(config or self.idp_config)
        for service, endpoint in self.endpoints.items():
            idp_endpoints = []
            for binding, path in endpoint.items():
                url = "{base}/{provider}/{target_id}/{path}".format(
                    base=self.base_url, provider=provider,
                    target_id=target_entity_id, path=path)
                idp_endpoints.append((url, binding))
            idp_conf["service"]["idp"]["endpoints"][service] = idp_endpoints
        return idp_conf

    def _load_idp_dynamic_endpoints(self, context):
        """
        Loads an idp server that accepts the target backend name in the endpoint url
         ex: /<backend_name>/sso/redirect

        :type context: The current context
        :rtype: saml.server.Server

        :param context:
        :return: An idp server
        """
        target_entity_id = context.path.split("/")[1]
        context.internal_data["mirror.target_entity_id"] = target_entity_id
        idp_conf_file = self._load_endpoints_to_config(context.target_backend, target_entity_id)
        idp_config = IdPConfig().load(idp_conf_file, metadata_construction=False)
        return Server(config=idp_config)

    def _load_idp_dynamic_entity_id(self, state):
        """
        Loads an idp server with the entity id saved in state

        :type state: satosa.state.State
        :rtype: saml.server.Server

        :param state: The current state
        :return: An idp server
        """
        # Change the idp entity id dynamically
        idp_config_file = copy.deepcopy(self.idp_config)
        idp_config_file["entityid"] = "{}/{}".format(self.idp_config["entityid"], state[self.name]["target_entity_id"])
        idp_config = IdPConfig().load(idp_config_file, metadata_construction=False)
        return Server(config=idp_config)

    def handle_authn_request(self, context, binding_in):
        """
        Loads approved endpoints dynamically
        See super class satosa.frontends.saml2.SAMLFrontend#handle_authn_request

        :type context: satosa.context.Context
        :type binding_in: str
        :rtype: satosa.response.Response
        """
        idp = self._load_idp_dynamic_endpoints(context)
        return self._handle_authn_request(context, binding_in, idp)

    def _create_state_data(self, context, resp_args, relay_state):
        """
        Adds the frontend idp entity id to state
        See super class satosa.frontends.saml2.SAMLFrontend#save_state

        :type context: satosa.context.Context
        :type resp_args: dict[str, str | saml2.samlp.NameIDPolicy]
        :type relay_state: str
        :rtype: dict[str, dict[str, str] | str]
        """
        state = super()._create_state_data(context, resp_args, relay_state)
        state["target_entity_id"] = context.path.split("/")[1]
        return state

    def handle_backend_error(self, exception):
        """
        Loads the frontend entity id dynamically.
        See super class satosa.frontends.saml2.SAMLFrontend#handle_backend_error
        :type exception: satosa.exception.SATOSAAuthenticationError
        :rtype: satosa.response.Response
        """
        idp = self._load_idp_dynamic_entity_id(exception.state)
        return self._handle_backend_error(exception, idp)

    def handle_authn_response(self, context, internal_response):
        """
        See super class satosa.frontends.base.FrontendModule#handle_authn_response
        :param context:
        :param internal_response:
        :return:
        """
        idp = self._load_idp_dynamic_entity_id(context.state)
        return self._handle_authn_response(context, internal_response, idp)

    def _register_endpoints(self, providers):
        """
        See super class satosa.frontends.base.FrontendModule#register_endpoints

        :type providers: list[str]
        :rtype list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))] |
               list[(str, (satosa.context.Context) -> satosa.response.Response)]
        :param providers: A list with backend names
        :return: A list of url and endpoint function pairs
        """
        url_map = []

        for endp_category in self.endpoints:
            for binding, endp in self.endpoints[endp_category].items():
                valid_providers = "|^".join(providers)
                parsed_endp = urlparse(endp)
                url_map.append(("(^%s)/\S+/%s" % (valid_providers, parsed_endp.path),
                                functools.partial(self.handle_authn_request, binding_in=binding)))

        return url_map
