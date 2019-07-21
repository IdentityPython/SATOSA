"""
A pysaml2 frontend module for the satosa proxy
"""
import copy
import functools
import json
import logging
import re
from base64 import urlsafe_b64decode
from base64 import urlsafe_b64encode
from urllib.parse import quote
from urllib.parse import quote_plus
from urllib.parse import unquote
from urllib.parse import unquote_plus
from urllib.parse import urlparse
from http.cookies import SimpleCookie

from saml2 import SAMLError, xmldsig
from saml2.config import IdPConfig
from saml2.extension.ui import NAMESPACE as UI_NAMESPACE
from saml2.metadata import create_metadata_string
from saml2.saml import NameID
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2.samlp import name_id_policy_from_string
from saml2.server import Server

from satosa.base import SAMLBaseModule
from satosa.context import Context
from .base import FrontendModule
from ..logging_util import satosa_logging
from ..response import Response
from ..response import ServiceError
from ..saml_util import make_saml_response
from satosa.exception import SATOSAError
import satosa.util as util

from satosa.internal import InternalData
from satosa.deprecated import saml_name_id_format_to_hash_type
from satosa.deprecated import hash_type_to_saml_name_id_format


logger = logging.getLogger(__name__)


subject_type_map = {
    NAMEID_FORMAT_TRANSIENT: NAMEID_FORMAT_TRANSIENT,
    NAMEID_FORMAT_PERSISTENT: NAMEID_FORMAT_PERSISTENT,
    NAMEID_FORMAT_EMAILADDRESS: NAMEID_FORMAT_EMAILADDRESS,
    NAMEID_FORMAT_UNSPECIFIED: NAMEID_FORMAT_UNSPECIFIED,
    "public": NAMEID_FORMAT_PERSISTENT,
    "pairwise": NAMEID_FORMAT_TRANSIENT,
}


def subject_type_to_saml_nameid_format(subject_type):
    return subject_type_map.get(subject_type, NAMEID_FORMAT_PERSISTENT)


class SAMLFrontend(FrontendModule, SAMLBaseModule):
    """
    A pysaml2 frontend module
    """
    KEY_CUSTOM_ATTR_RELEASE = 'custom_attribute_release'
    KEY_ENDPOINTS = 'endpoints'
    KEY_IDP_CONFIG = 'idp_config'

    def __init__(self, auth_req_callback_func, internal_attributes, config, base_url, name):
        self._validate_config(config)

        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)
        self.config = self.init_config(config)

        self.endpoints = config[self.KEY_ENDPOINTS]
        self.custom_attribute_release = config.get(
            self.KEY_CUSTOM_ATTR_RELEASE)
        self.idp = None

    def handle_authn_response(self, context, internal_response):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
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
        self.idp_config = self._build_idp_config_endpoints(
            self.config[self.KEY_IDP_CONFIG], backend_names)
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
        required_keys = [
            self.KEY_IDP_CONFIG,
            self.KEY_ENDPOINTS,
        ]

        if not config:
            raise ValueError("No configuration given")

        for key in required_keys:
            try:
                _val = config[key]
            except KeyError as e:
                raise ValueError("Missing configuration key: %s" % key) from e

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

        # keep the ForceAuthn value to be used by plugins
        context.decorate(Context.KEY_FORCE_AUTHN, authn_req.force_authn)

        try:
            resp_args = idp.response_args(authn_req)
        except SAMLError as e:
            satosa_logging(logger, logging.ERROR, "Could not find necessary info about entity: %s" % e, context.state)
            return ServiceError("Incorrect request from requester: %s" % e)

        requester = resp_args["sp_entity_id"]
        context.state[self.name] = self._create_state_data(context, idp.response_args(authn_req),
                                                           context.request.get("RelayState"))

        subject = authn_req.subject
        name_id_value = subject.name_id.text if subject else None

        nameid_formats = {
            "from_policy": authn_req.name_id_policy and authn_req.name_id_policy.format,
            "from_response": subject and subject.name_id and subject.name_id.format,
            "from_metadata": (
                idp.metadata[requester]
                .get("spsso_descriptor", [{}])[0]
                .get("name_id_format", [{}])[0]
                .get("text")
            ),
            "default": NAMEID_FORMAT_TRANSIENT,
        }

        name_id_format = (
            nameid_formats["from_policy"]
            or (
                nameid_formats["from_response"] != NAMEID_FORMAT_UNSPECIFIED
                and nameid_formats["from_response"]
            )
            or nameid_formats["from_metadata"]
            or nameid_formats["from_response"]
            or nameid_formats["default"]
        )

        requester_name = self._get_sp_display_name(idp, requester)
        internal_req = InternalData(
            subject_id=name_id_value,
            subject_type=name_id_format,
            requester=requester,
            requester_name=requester_name,
        )

        idp_policy = idp.config.getattr("policy", "idp")
        if idp_policy:
            internal_req.attributes = self._get_approved_attributes(
                idp, idp_policy, requester, context.state
            )

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
        attributes = {}
        if idp_policy:
            approved_attributes = self._get_approved_attributes(idp, idp_policy, internal_response.requester,
                                                                context.state)
            attributes = {k: v for k, v in internal_response.attributes.items() if k in approved_attributes}

        return attributes

    def _handle_authn_response(self, context, internal_response, idp):
        """
        See super class satosa.frontends.base.FrontendModule

        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
        :type idp: saml.server.Server

        :param context: The current context
        :param internal_response: The internal response
        :param idp: The saml frontend idp server
        :return: A saml response
        """
        request_state = self.load_state(context.state)

        resp_args = request_state["resp_args"]
        sp_entity_id = resp_args["sp_entity_id"]
        internal_response.attributes = self._filter_attributes(
            idp, internal_response, context)
        ava = self.converter.from_internal(
            self.attribute_profile, internal_response.attributes)

        auth_info = {}
        if self.acr_mapping:
            auth_info["class_ref"] = self.acr_mapping.get(
                internal_response.auth_info.issuer, self.acr_mapping[""])
        else:
            auth_info["class_ref"] = internal_response.auth_info.auth_class_ref

        auth_info["authn_auth"] = internal_response.auth_info.issuer

        if self.custom_attribute_release:
            custom_release = util.get_dict_defaults(
                self.custom_attribute_release,
                internal_response.auth_info.issuer,
                sp_entity_id)
            attributes_to_remove = custom_release.get("exclude", [])
            for k in attributes_to_remove:
                ava.pop(k, None)

        nameid_value = internal_response.subject_id
        nameid_format = subject_type_to_saml_nameid_format(
            internal_response.subject_type
        )

        # If the backend did not receive a SAML <NameID> and so
        # name_id is set to None then do not create a NameID instance.
        # Instead pass None as the name name_id to the IdP server
        # instance and it will use its configured policy to construct
        # a <NameID>, with the default to create a transient <NameID>.
        name_id = None if not nameid_value else NameID(
            text=nameid_value,
            format=nameid_format,
            sp_name_qualifier=None,
            name_qualifier=None,
        )

        dbgmsg = "returning attributes %s" % json.dumps(ava)
        satosa_logging(logger, logging.DEBUG, dbgmsg, context.state)

        policies = self.idp_config.get(
            'service', {}).get('idp', {}).get('policy', {})
        sp_policy = policies.get('default', {})
        sp_policy.update(policies.get(sp_entity_id, {}))

        sign_assertion = sp_policy.get('sign_assertion', False)
        sign_response = sp_policy.get('sign_response', True)
        sign_alg = sp_policy.get('sign_alg', 'SIG_RSA_SHA256')
        digest_alg = sp_policy.get('digest_alg', 'DIGEST_SHA256')

        # Construct arguments for method create_authn_response
        # on IdP Server instance
        args = {
            'identity'      : ava,
            'name_id'       : name_id,
            'authn'         : auth_info,
            'sign_response' : sign_response,
            'sign_assertion': sign_assertion,
        }

        # Add the SP details
        args.update(**resp_args)

        try:
            args['sign_alg'] = getattr(xmldsig, sign_alg)
        except AttributeError as e:
            errmsg = "Unsupported sign algorithm %s" % sign_alg
            satosa_logging(logger, logging.ERROR, errmsg, context.state)
            raise Exception(errmsg) from e
        else:
            dbgmsg = "signing with algorithm %s" % args['sign_alg']
            satosa_logging(logger, logging.DEBUG, dbgmsg, context.state)

        try:
            args['digest_alg'] = getattr(xmldsig, digest_alg)
        except AttributeError as e:
            errmsg = "Unsupported digest algorithm %s" % digest_alg
            satosa_logging(logger, logging.ERROR, errmsg, context.state)
            raise Exception(errmsg) from e
        else:
            dbgmsg = "using digest algorithm %s" % args['digest_alg']
            satosa_logging(logger, logging.DEBUG, dbgmsg, context.state)

        resp = idp.create_authn_response(**args)
        http_args = idp.apply_binding(
            resp_args["binding"], str(resp), resp_args["destination"],
            request_state["relay_state"], response=True)

        # Set the common domain cookie _saml_idp if so configured.
        if self.config.get('common_domain_cookie'):
            self._set_common_domain_cookie(internal_response, http_args, context)

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

        if self.expose_entityid_endpoint():
            parsed_entity_id = urlparse(self.idp.config.entityid)
            url_map.append(("^{0}".format(parsed_entity_id.path[1:]),
                            self._metadata_endpoint))

        return url_map

    def _set_common_domain_cookie(self, internal_response, http_args, context):
        """
        """
        # Find any existing common domain cookie and deconsruct it to
        # obtain the list of IdPs.
        cookie = SimpleCookie(context.cookie)
        if '_saml_idp' in cookie:
            common_domain_cookie = cookie['_saml_idp']
            satosa_logging(logger, logging.DEBUG, "Found existing common domain cookie {}".format(common_domain_cookie), context.state)
            space_separated_b64_idp_string = unquote(common_domain_cookie.value)
            b64_idp_list = space_separated_b64_idp_string.split()
            idp_list = [urlsafe_b64decode(b64_idp).decode('utf-8') for b64_idp in b64_idp_list]
        else:
            satosa_logging(logger, logging.DEBUG, "No existing common domain cookie found", context.state)
            idp_list = []

        satosa_logging(logger, logging.DEBUG, "Common domain cookie list of IdPs is {}".format(idp_list), context.state)

        # Identity the current IdP just used for authentication in this flow.
        this_flow_idp = internal_response.auth_info.issuer

        # Remove all occurrences of the current IdP from the list of IdPs.
        idp_list = [idp for idp in idp_list if idp != this_flow_idp]

        # Append the current IdP.
        idp_list.append(this_flow_idp)
        satosa_logging(logger, logging.DEBUG, "Added IdP {} to common domain cookie list of IdPs".format(this_flow_idp), context.state)
        satosa_logging(logger, logging.DEBUG, "Common domain cookie list of IdPs is now {}".format(idp_list), context.state)

        # Construct the cookie.
        b64_idp_list = [urlsafe_b64encode(idp.encode()).decode("utf-8") for idp in idp_list]
        space_separated_b64_idp_string = " ".join(b64_idp_list)
        url_encoded_space_separated_b64_idp_string = quote(space_separated_b64_idp_string)

        cookie = SimpleCookie()
        cookie['_saml_idp'] = url_encoded_space_separated_b64_idp_string
        cookie['_saml_idp']['path'] = '/'

        # Use the domain from configuration if present else use the domain
        # from the base URL for the front end.
        domain = urlparse(self.base_url).netloc
        if isinstance(self.config['common_domain_cookie'], dict):
            if 'domain' in self.config['common_domain_cookie']:
                domain = self.config['common_domain_cookie']['domain']

        # Ensure that the domain begins with a '.'
        if domain[0] != '.':
            domain = '.' + domain

        cookie['_saml_idp']['domain'] = domain
        cookie['_saml_idp']['secure'] = True

        # Set the cookie.
        satosa_logging(logger, logging.DEBUG, "Setting common domain cookie with {}".format(cookie.output()), context.state)
        http_args['headers'].append(tuple(cookie.output().split(": ", 1)))

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
        target_entity_id = context.target_entity_id_from_path()
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
        target_entity_id = context.target_entity_id_from_path()
        target_entity_id = urlsafe_b64decode(target_entity_id).decode()
        context.decorate(Context.KEY_TARGET_ENTITYID, target_entity_id)

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
        state["target_entity_id"] = context.target_entity_id_from_path()
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


class SAMLVirtualCoFrontend(SAMLFrontend):
    """
    Frontend module that exposes multiple virtual SAML identity providers,
    each representing a collaborative organization or CO.
    """
    KEY_CO = 'collaborative_organizations'
    KEY_CO_NAME = 'co_name'
    KEY_CO_ENTITY_ID = 'co_entity_id'
    KEY_CO_ATTRIBUTES = 'co_static_saml_attributes'
    KEY_CONTACT_PERSON = 'contact_person'
    KEY_ENCODEABLE_NAME = 'encodeable_name'
    KEY_ORGANIZATION = 'organization'
    KEY_ORGANIZATION_KEYS = ['display_name', 'name', 'url']

    def handle_authn_request(self, context, binding_in):
        """
        See super class
        satosa.frontends.saml2.SAMLFrontend#handle_authn_request

        :type context: satosa.context.Context
        :type binding_in: str
        :rtype: satosa.response.Response
        """

        # Using the context of the current request dynamically create an
        # IdP instance and then use it to handle the authentication request.
        idp = self._create_co_virtual_idp(context)
        return self._handle_authn_request(context, binding_in, idp)

    def handle_authn_response(self, context, internal_response):
        """
        See super class satosa.frontends.base.
                        FrontendModule#handle_authn_response
        :param context:
        :param internal_response:
        :return:
        """

        return self._handle_authn_response(context, internal_response)

    def _handle_authn_response(self, context, internal_response):
        """
        """
        # Using the context of the current request and saved state from the
        # authentication request dynamically create an IdP instance.
        idp = self._create_co_virtual_idp(context)

        # Add any static attributes for the CO.
        co_config = self._get_co_config(context)

        if self.KEY_CO_ATTRIBUTES in co_config:
            attributes = internal_response.attributes
            for attribute, value in co_config[self.KEY_CO_ATTRIBUTES].items():
                # XXX This should be refactored when Python 3.4 support is
                # XXX no longer required to use isinstance(value, Iterable).
                try:
                    if iter(value) and not isinstance(value, str):
                        attributes[attribute] = value
                    else:
                        attributes[attribute] = [value]
                except TypeError:
                        attributes[attribute] = [value]

        # Handle the authentication response.
        return super()._handle_authn_response(context, internal_response, idp)

    def _create_state_data(self, context, resp_args, relay_state):
        """
        Adds the CO name to state
        See super class satosa.frontends.saml2.SAMLFrontend#save_state

        :type context: satosa.context.Context
        :type resp_args: dict[str, str | saml2.samlp.NameIDPolicy]
        :type relay_state: str
        :rtype: dict[str, dict[str, str] | str]
        """
        state = super()._create_state_data(context, resp_args, relay_state)
        state[self.KEY_CO_NAME] = context.get_decoration(self.KEY_CO_NAME)
        state[self.KEY_CO_ENTITY_ID] = context.get_decoration(
                                                         self.KEY_CO_ENTITY_ID)

        return state

    def _get_co_config(self, context):
        """
        Obtain the configuration for the CO.

        :type context: The current context
        :rtype: dict

        :param context: The current context
        :return: CO configuration

        """
        co_name = self._get_co_name(context)
        for co in self.config[self.KEY_CO]:
            if co[self.KEY_ENCODEABLE_NAME] == co_name:
                return co

    def _get_co_name_from_path(self, context):
        """
        The CO name is URL encoded and obtained from the request path
        for a request coming into one of the standard binding endpoints.
        For example the HTTP-Redirect binding request path will have the
        format

        {base}/{backend}/{co_name}/sso/redirect

        :type context: satosa.context.Context
        :rtype: str

        :param context:

        """
        url_encoded_co_name = context.path.split("/")[1]
        co_name = unquote_plus(url_encoded_co_name)

        return co_name

    def _get_co_name(self, context):
        """
        Obtain the CO name previously saved in the request state, or if not set
        use the request path obtained from the current context to determine
        the target CO.

        :type context: The current context
        :rtype: string

        :param context: The current context
        :return: CO name
        """
        try:
            co_name = context.state[self.name][self.KEY_CO_NAME]
            logger.debug("Found CO {} from state".format(co_name))
        except KeyError:
            co_name = self._get_co_name_from_path(context)
            logger.debug("Found CO {} from request path".format(co_name))

        return co_name

    def _add_endpoints_to_config(self, config, co_name, backend_name):
        """
        Use the request path from the context to determine the target backend,
        then construct mappings from bindings to endpoints for the virtual
        IdP for the CO.

        The endpoint URLs have the form

        {base}/{backend}/{co_name}/{path}

        :type config: satosa.satosa_config.SATOSAConfig
        :type co_name: str
        :type backend_name: str
        :rtype: satosa.satosa_config.SATOSAConfig

        :param config: satosa proxy config
        :param co_name: CO name
        :param backend_name: The target backend name

        :return: config with mappings for CO IdP
        """

        for service, endpoint in self.endpoints.items():
            idp_endpoints = []
            for binding, path in endpoint.items():
                url = "{base}/{backend}/{co_name}/{path}".format(
                      base=self.base_url,
                      backend=backend_name,
                      co_name=quote_plus(co_name),
                      path=path)
                mapping = (url, binding)
                idp_endpoints.append(mapping)

            # Overwrite the IdP config with the CO specific mappings between
            # SAML binding and URL endpoints.
            config["service"]["idp"]["endpoints"][service] = idp_endpoints

        return config

    def _add_entity_id(self, context, config, co_name):
        """
        Use the CO name to construct the entity ID for the virtual IdP
        for the CO and add it to the config. Also add it to the
        context.

        The entity ID has the form

        {base_entity_id}/{co_name}

        :type context: The current context
        :type config: satosa.satosa_config.SATOSAConfig
        :type co_name: str
        :rtype: satosa.satosa_config.SATOSAConfig

        :param context:
        :param config: satosa proxy config
        :param co_name: CO name

        :return: config with updated entity ID
        """
        base_entity_id = config['entityid']
        co_entity_id = "{}/{}".format(base_entity_id, quote_plus(co_name))
        config['entityid'] = co_entity_id
        context.decorate(self.KEY_CO_ENTITY_ID, co_entity_id)

        return config

    def _overlay_for_saml_metadata(self, config, co_name):
        """
        Overlay configuration details like organization and contact person
        from the front end configuration onto the IdP configuration to
        support SAML metadata generation.

        :type config: satosa.satosa_config.SATOSAConfig
        :type co_name: str
        :rtype: satosa.satosa_config.SATOSAConfig

        :param config: satosa proxy config
        :param co_name: CO name

        :return: config with updated details for SAML metadata
        """
        all_co_configs = self.config[self.KEY_CO]
        co_config = next(
            item for item in all_co_configs
            if item[self.KEY_ENCODEABLE_NAME] == co_name
        )

        key = self.KEY_ORGANIZATION
        if key in co_config:
            if key not in config:
                config[key] = {}
            for org_key in self.KEY_ORGANIZATION_KEYS:
                if org_key in co_config[key]:
                    config[key][org_key] = co_config[key][org_key]

        key = self.KEY_CONTACT_PERSON
        if key in co_config:
            config[key] = co_config[key]

        return config

    def _co_names_from_config(self):
        """
        Parse the configuration for the names of the COs for which to
        construct virtual IdPs.

        :rtype: [str]

        :return: list of CO names
        """
        co_names = [co[self.KEY_ENCODEABLE_NAME] for
                    co in self.config[self.KEY_CO]]

        return co_names

    def _create_co_virtual_idp(self, context):
        """
        Create a virtual IdP to represent the CO.

        :type context: The current context
        :rtype: saml.server.Server

        :param context:
        :return: An idp server
        """
        co_name = self._get_co_name(context)
        context.decorate(self.KEY_CO_NAME, co_name)

        # Verify that we are configured for this CO. If the CO was not
        # configured most likely the endpoint used was not registered and
        # SATOSA core code threw an exception before getting here, but we
        # include this check in case later the regex used to register the
        # endpoints is relaxed.
        co_names = self._co_names_from_config()
        if co_name not in co_names:
            msg = "CO {} not in configured list of COs {}".format(co_name,
                                                                  co_names)
            satosa_logging(logger, logging.WARN, msg, context.state)
            raise SATOSAError(msg)

        # Make a copy of the general IdP config that we will then overwrite
        # with mappings between SAML bindings and CO specific URL endpoints,
        # and the entityID for the CO virtual IdP.
        backend_name = context.target_backend
        idp_config = copy.deepcopy(self.idp_config)
        idp_config = self._add_endpoints_to_config(idp_config,
                                                   co_name,
                                                   backend_name)
        idp_config = self._add_entity_id(context, idp_config, co_name)

        # Use the overwritten IdP config to generate a pysaml2 config object
        # and from it a server object.
        pysaml2_idp_config = IdPConfig().load(idp_config,
                                              metadata_construction=False)

        server = Server(config=pysaml2_idp_config)

        return server

    def _register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule#register_endpoints

        Endpoints have the format

        {base}/{backend}/{co_name}/{binding path}

        For example the HTTP-Redirect binding request path will have the
        format

        {base}/{backend}/{co_name}/sso/redirect

        :type providers: list[str]
        :rtype list[(str, ((satosa.context.Context, Any) ->
                    satosa.response.Response, Any))] |
               list[(str, (satosa.context.Context) ->
                    satosa.response.Response)]
        :param backend_names: A list of backend names
        :return: A list of url and endpoint function pairs
        """
        # Create a regex pattern that will match any of the CO names. We
        # escape special characters like '+' and '.' that are valid
        # characters in an URL encoded string.
        co_names = self._co_names_from_config()
        url_encoded_co_names = [re.escape(quote_plus(name)) for name in
                                co_names]
        co_name_pattern = "|".join(url_encoded_co_names)

        # Create a regex pattern that will match any of the backend names.
        backend_url_pattern = "|^".join(backend_names)
        logger.debug("Input backend names are {}".format(backend_names))
        logger.debug("Created backend regex '{}'".format(backend_url_pattern))

        # Hold a list of tuples containing URL regex patterns and the callables
        # that handle them.
        url_to_callable_mappings = []

        # Loop over IdP endpoint categories, e.g., single_sign_on_service.
        for endpoint_category in self.endpoints:
            logger.debug("Examining endpoint category {}".format(
                                    endpoint_category))

            # For each endpoint category loop of the bindings and their
            # assigned endpoints.
            for binding, endpoint in self.endpoints[endpoint_category].items():
                logger.debug("Found binding {} and endpoint {}".format(binding,
                             endpoint))

                # Parse out the path from the endpoint.
                endpoint_path = urlparse(endpoint).path
                logger.debug("Using path {}".format(endpoint_path))

                # Use the backend URL pattern and the endpoint path to create
                # a regex that will match and that includes a pattern for
                # matching the URL encoded CO name.
                regex_pattern = "(^{})/({})/{}".format(
                                backend_url_pattern,
                                co_name_pattern,
                                endpoint_path)
                logger.debug("Created URL regex {}".format(regex_pattern))

                # Map the regex pattern to a callable.
                the_callable = functools.partial(self.handle_authn_request,
                                                 binding_in=binding)
                logger.debug("Created callable {}".format(the_callable))

                mapping = (regex_pattern, the_callable)
                url_to_callable_mappings.append(mapping)
                logger.debug("Adding mapping {}".format(mapping))

        return url_to_callable_mappings
