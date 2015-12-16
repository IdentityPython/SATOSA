#!/usr/bin/env python
"""
A pysaml2 frontend module for the satosa proxy
"""
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
from saml2.saml import NameID
from saml2.samlp import name_id_policy_from_string

from saml2.server import Server

from satosa.frontends.base import FrontendModule
from satosa.internal_data import InternalRequest, DataConverter
from satosa.logging_util import satosa_logging
from satosa.util import response, get_saml_name_id_format, saml_name_format_to_hash_type

LOGGER = logging.getLogger(__name__)


class SamlFrontend(FrontendModule):
    """
    A pysaml2 frontend module
    """

    def __init__(self, auth_req_callback_func, internal_attributes, conf):
        if conf is None:
            raise TypeError("conf can't be 'None'")
        self._validate_config(conf)

        super(SamlFrontend, self).__init__(auth_req_callback_func, internal_attributes)
        if internal_attributes is not None:
            self.converter = DataConverter(internal_attributes)
        self.config = conf["idp_config"]
        self.endpoints = conf["endpoints"]
        self.base = conf["base"]
        self.state_id = conf["state_id"]
        self.response_bindings = None
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

    def register_endpoints(self, providers):
        """
        See super class satosa.frontends.base.FrontendModule
        :type providers: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        """
        self._validate_providers(providers)
        self.config = self._build_idp_config_endpoints(self.config, providers)
        # Create the idp
        idp_config = IdPConfig().load(copy.deepcopy(self.config), metadata_construction=False)
        self.idp = Server(config=idp_config)
        return self._register_endpoints(providers)

    def save_state(self, context, resp_args, relay_state):
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
        resp_args["name_id_policy"] = resp_args["name_id_policy"].to_string().decode("utf-8")
        return {"resp_args": resp_args,
                "relay_state": relay_state}

    def load_state(self, state):
        """
        Loads a state from state
        :type state: satosa.state.State
        :rtype: dict[str, Any]
        :param state: The current state
        :return: The dictionary given by the save_state function
        """
        loaded_state = state.get(self.state_id)
        if isinstance(loaded_state["resp_args"]["name_id_policy"], str):
            loaded_state["resp_args"]["name_id_policy"] = name_id_policy_from_string(
                loaded_state["resp_args"]["name_id_policy"])
        return loaded_state

    def _validate_config(self, config):
        """
        Validates some parts of the module config
        :type config: dict[str, dict[str, Any] | str]
        :param config: The module config
        """
        mandatory_keys = ["idp_config", "endpoints", "base"]
        for key in mandatory_keys:
            assert key in config, "Missing key '%s' in config" % key

    def extract_request(self, idp, query, binding, state):
        """
        Extracts response arguments, the response, authentication request and request arguments from
        the saml request.

        :type idp: saml2.server.Server
        :type query: str
        :type binding: str
        :type state: satosa.state.State
        :rtype: dict[str, Any]

        :param idp: The frontend saml server
        :param query: The SAML request
        :param binding: The binding type (http post, http redirect, ...)
        :param state: The current state
        :return: A dict containing response arguments, the response, authentication request and
        request arguments
        """
        if not query:
            satosa_logging(LOGGER, logging.WARN, "Missing QUERY", state)
            resp = Unauthorized('Unknown user')
            return {"response": resp}

        req_info = idp.parse_authn_request(query, binding)

        _authn_req = req_info.message
        satosa_logging(LOGGER, logging.DEBUG, "%s" % _authn_req, state)

        # Check that I know where to send the reply to
        try:
            binding_out, destination = idp.pick_binding(
                "assertion_consumer_service",
                bindings=self.response_bindings,
                entity_id=_authn_req.issuer.text, request=_authn_req)
        except Exception as error:
            satosa_logging(LOGGER, logging.ERROR, "Couldn't find receiver endpoint", state,
                           exc_info=True)
            raise

        satosa_logging(LOGGER, logging.DEBUG, "Binding: %s, destination: %s" %
                       (binding_out, destination), state)

        resp_args = {}
        try:
            resp_args = idp.response_args(_authn_req)
            _resp = None
        except UnknownPrincipal as excp:
            satosa_logging(LOGGER, logging.ERROR, "Unknown principal name: %s" % excp, state)
            _resp = idp.create_error_response(_authn_req.id,
                                              destination, excp)
        except UnsupportedBinding as excp:
            satosa_logging(LOGGER, logging.ERROR, "Unknown unsupported binding: %s" % excp, state)
            _resp = idp.create_error_response(_authn_req.id,
                                              destination, excp)

        req_args = {}
        for key in ["subject", "name_id_policy", "conditions", "requested_authn_context",
                    "scoping", "force_authn", "is_passive"]:
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
        request = context.request

        try:
            extracted_request = self.extract_request(idp, request["SAMLRequest"], binding_in,
                                                     context.state)
        except UnknownPrincipal as excp:
            satosa_logging(LOGGER, logging.ERROR, "UnknownPrincipal", context.state, exc_info=True)
            return ServiceError("UnknownPrincipal: %s" % excp)
        except UnsupportedBinding as excp:
            satosa_logging(LOGGER, logging.ERROR, "UnsupportedBinding", context.state,
                           exc_info=True)
            return ServiceError("UnsupportedBinding: %s" % excp)

        _binding = extracted_request["resp_args"]["binding"]
        if extracted_request["response"]:  # An error response
            http_args = idp.apply_binding(
                _binding, "%s" % extracted_request["response"],
                extracted_request["resp_args"]["destination"],
                request["RelayState"], response=True)

            satosa_logging(LOGGER, logging.DEBUG, "HTTPargs: %s" % http_args, context.state,
                           exc_info=True)
            return response(_binding, http_args)
        else:

            try:
                context.internal_data["saml2.target_entity_id"] = request["entityID"]
            except KeyError:
                pass

            request_state = self.save_state(context,
                                            idp.response_args(extracted_request["authn_req"]),
                                            request["RelayState"])
            context.state.add(self.state_id, request_state)

            extensions = idp.metadata.extension(
                extracted_request['resp_args']['sp_entity_id'],
                'spsso_descriptor',
                'urn:oasis:names:tc:SAML:metadata:ui&UIInfo'
            )

            requester_name = None
            try:
                requester_name = extensions[0]['display_name']
            except IndexError:
                pass

            internal_req = InternalRequest(
                saml_name_format_to_hash_type(extracted_request['req_args']
                                              ['name_id_policy'].format),
                extracted_request["resp_args"]["sp_entity_id"],
                requester_name
            )

            # Get attribute filter
            idp_policy = idp.config.getattr("policy", "idp")
            if idp_policy:
                attribute_filter = self.get_filter_attributes(idp,
                                                              idp_policy,
                                                              internal_req.requestor,
                                                              context.state)
                internal_req.add_filter(attribute_filter)

            return self.auth_req_callback_func(context, internal_req)

    def get_filter_attributes(self, idp, idp_policy, sp_entity_id, state):
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
        attribute_filter = []
        for aconv in attrconvs:
            if aconv.name_format == name_format:
                attribute_filter = list(
                    idp_policy.restrict(aconv._to, sp_entity_id, idp.metadata).keys())
        attribute_filter = self.converter.to_internal_filter("saml", attribute_filter, True)
        satosa_logging(LOGGER, logging.DEBUG, "Filter: %s" % attribute_filter, state)
        return attribute_filter

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
        ava = self.converter.from_internal("saml", internal_response.get_attributes())
        auth_info = {"class_ref": internal_response.auth_info.auth_class_ref}

        name_id = NameID(text=internal_response.get_user_id(),
                         format=get_saml_name_id_format(internal_response.user_id_hash_type),
                         sp_name_qualifier=None,
                         name_qualifier=None)

        # Will signed the response by default
        resp = self.construct_authn_response(idp,
                                             context.state,
                                             ava,
                                             name_id=name_id,
                                             authn=auth_info,
                                             resp_args=resp_args,
                                             relay_state=request_state["relay_state"],
                                             sign_response=True)

        return resp

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
        http_args = idp.apply_binding(
            resp_args["binding"], "%s" % error_resp,
            resp_args["destination"],
            relay_state, response=True)

        satosa_logging(LOGGER, logging.DEBUG, "HTTPargs: %s" % http_args, exception.state)
        return response(resp_args["binding"], http_args)

    def construct_authn_response(self, idp, state, identity, name_id, authn, resp_args, relay_state,
                                 sign_response=True):
        """
        Constructs an auth response

        :type idp: saml.server.Server
        :type state: satosa.state.State
        :type identity: dict[str, str]
        :type name_id: saml2.saml.NameID
        :type authn: dict[str, str]
        :type resp_args: dict[str, str]
        :type relay_state: str
        :type sign_response: bool

        :param idp: The saml frontend idp server
        :param state: The current state
        :param identity: Information about an user (The ava attributes)
        :param name_id: The name id
        :param authn: auth info
        :param resp_args: response arguments
        :param relay_state: the relay state
        :param sign_response: Flag for signing the response or not
        :return: The constructed response
        """

        _resp = idp.create_authn_response(identity,
                                          name_id=name_id,
                                          authn=authn,
                                          sign_response=sign_response,
                                          **resp_args)

        http_args = idp.apply_binding(
            resp_args["binding"], "%s" % _resp, resp_args["destination"],
            relay_state, response=True)

        satosa_logging(LOGGER, logging.DEBUG, "HTTPargs: %s" % http_args, state)

        resp = None
        if http_args["data"]:
            resp = Response(http_args["data"], headers=http_args["headers"])
        else:
            for header in http_args["headers"]:
                if header[0] == "Location":
                    resp = Redirect(header[1])

        if not resp:
            msg = "Don't know how to return response"
            satosa_logging(LOGGER, logging.ERROR, msg, state)
            resp = ServiceError(msg)

        return resp

    def _validate_providers(self, providers):
        """
        Validate the provider list
        :type providers: list[str]
        :param providers: A list with provider names (name of the backends)
        """
        if providers is None or not isinstance(providers, list):
            msg = "'providers' is not 'list' type"
            LOGGER.error(msg)
            raise TypeError(msg)

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
                                (self.handle_authn_request, binding)))
                url_map.append(("(%s)/%s/(.*)$" % (valid_providers, parsed_endp.path),
                                (self.handle_authn_request, binding)))

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
        for endp_category in self.endpoints.keys():
            for func, endpoint in self.endpoints[endp_category].items():
                for provider in providers:
                    _endpoint = "{base}/{provider}/{endpoint}".format(
                        base=self.base, provider=provider, endpoint=endpoint)
                    idp_endpoints.append((_endpoint, func))
            config["service"]["idp"]["endpoints"][endp_category] = idp_endpoints

        return config


class SamlMirrorFrontend(SamlFrontend):
    """
    Frontend module that uses dynamic entity id and partially dynamic endpoints.
    """

    @staticmethod
    def _load_endpoints_to_config(frontend_config, frontend_endpoints, url_base, provider,
                                  target_entity_id):
        """
        Loads approved endpoints to the config.

        :type frontend_config: dict[str, Any]
        :type frontend_endpoints: dict[str, dict[str, str]]
        :type url_base: str
        :type provider: str
        :type target_entity_id: str
        :rtype: dict[str, Any]

        :param frontend_config: Idp config
        :param frontend_endpoints: A map between binding type and endpoint url for services
            ex {"single_sign_on_service": {BINDING_HTTP_REDIRECT: "sso/redirect",
                                           BINDING_HTTP_POST: "sso/post"}}
        :param url_base: The proxy base url
        :param provider: target backend name
        :param target_entity_id: frontend target entity id
        :return: IDP config with endpoints
        """
        idp_conf_file = copy.deepcopy(frontend_config)
        idp_endpoints = []
        for endp_category in frontend_endpoints.keys():
            for func, endpoint in frontend_endpoints[endp_category].items():
                endpoint = "{base}/{provider}/{target_id}/{endpoint}".format(
                    base=url_base, provider=provider,
                    target_id=target_entity_id, endpoint=endpoint)
                idp_endpoints.append((endpoint, func))
            idp_conf_file["service"]["idp"]["endpoints"][endp_category] = idp_endpoints
        return idp_conf_file

    @staticmethod
    def _load_entity_id_to_config(proxy_entity_id, second_entity_id, config):
        """
        Setts an entity id in an idp config. The entity id is based on the proxy id and target id

        :type proxy_entity_id: str
        :type second_entity_id: str
        :type config: dict[str, Any]

        :param proxy_entity_id: The proxy entity id given in proxy config
        :param second_entity_id: Second part of the target entity id
        :param config: The idp config
        :return: The idp config file containing the target entity id
        """
        config["entityid"] = "{}/{}".format(proxy_entity_id, second_entity_id)
        return config

    def _get_target_entity_id(self, context):
        """
        Retrieves the target entity id from the context path
        :type context: satosa.context.Context
        :rtype: str
        :param context: the current context
        :return: target entity id
        """
        return context.path.lstrip("/").split('/')[1]

    def _load_idp_dynamic_endpoints(self, context):
        """
        Loads an idp server that accepts the target backend name in the endpoint url
         ex: /<backend_name>/sso/redirect

        :type context: The current context
        :rtype: saml.server.Server

        :param context:
        :return: An idp server
        """
        target_entity_id = self._get_target_entity_id(context)
        context.internal_data["mirror.target_entity_id"] = target_entity_id
        idp_conf_file = self._load_endpoints_to_config(self.config, self.endpoints, self.base,
                                                       context.target_backend, target_entity_id)
        idp_config = IdPConfig().load(idp_conf_file, metadata_construction=False)
        return Server(config=idp_config)

    def _load_idp_dynamic_entity_id(self, config, state):
        """
        Loads an idp server with the entity id saved in state

        :type config: dict[str, Any]
        :type state: satosa.state.State
        :rtype: saml.server.Server

        :param config: The module config
        :param state: The current state
        :return: An idp server
        """
        request_state = self.load_state(state)
        # Change the idp entity id dynamically
        idp_config_file = copy.deepcopy(config)
        idp_config_file = self._load_entity_id_to_config(config["entityid"],
                                                         request_state["proxy_idp_entityid"],
                                                         idp_config_file)
        idp_config = IdPConfig().load(idp_config_file, metadata_construction=False)
        return Server(config=idp_config)

    def handle_authn_request(self, context, binding_in):
        """
        Loads approved endpoints dynamically
        See super class satosa.frontends.saml2.SamlFrontend#handle_authn_request

        :type context: satosa.context.Context
        :type binding_in: str
        :rtype: satosa.response.Response
        """
        idp = self._load_idp_dynamic_endpoints(context)
        return self._handle_authn_request(context, binding_in, idp)

    def save_state(self, context, resp_args, relay_state):
        """
        Adds the frontend idp entity id to state
        See super class satosa.frontends.saml2.SamlFrontend#save_state

        :type context: satosa.context.Context
        :type resp_args: dict[str, str | saml2.samlp.NameIDPolicy]
        :type relay_state: str
        :rtype: dict[str, dict[str, str] | str]
        """
        state = super(SamlMirrorFrontend, self).save_state(context, resp_args, relay_state)
        state["proxy_idp_entityid"] = self._get_target_entity_id(context)
        return state

    def handle_backend_error(self, exception):
        """
        Loads the frontend entity id dynamically.
        See super class satosa.frontends.saml2.SamlFrontend#handle_backend_error
        :type exception: satosa.exception.SATOSAAuthenticationError
        :rtype: satosa.response.Response
        """
        idp = self._load_idp_dynamic_entity_id(self.config, exception.state)
        return self._handle_backend_error(exception, idp)

    def handle_authn_response(self, context, internal_response):
        """
        See super class satosa.frontends.base.FrontendModule#handle_authn_response
        :param context:
        :param internal_response:
        :return:
        """
        idp = self._load_idp_dynamic_entity_id(self.config, context.state)
        return self._handle_authn_response(context, internal_response, idp)

    def register_endpoints(self, providers):
        """
        See super class satosa.frontends.base.FrontendModule#register_endpoints

        :type providers: list[str]
        :rtype list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))] |
               list[(str, (satosa.context.Context) -> satosa.response.Response)]
        :param providers: A list with backend names
        :return: A list of url and endpoint function pairs
        """
        self._validate_providers(providers)

        url_map = []

        for endp_category in self.endpoints:
            for binding, endp in self.endpoints[endp_category].items():
                valid_providers = ""
                for provider in providers:
                    valid_providers = "{}|^{}".format(valid_providers, provider)
                valid_providers = valid_providers.lstrip("|")
                parsed_endp = urlparse(endp)
                url_map.append(("(%s)/[\s\S]+/%s$" % (valid_providers, parsed_endp.path),
                                (self.handle_authn_request, binding)))
                url_map.append(("(%s)/[\s\S]+/%s/(.*)$" % (valid_providers, parsed_endp.path),
                                (self.handle_authn_request, binding)))

        return url_map
