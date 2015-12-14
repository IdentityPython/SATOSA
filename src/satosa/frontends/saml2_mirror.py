"""
A frontend module for SATOSA that mirrors the target idp/op to the frontend metadata
"""
import copy
import logging
from saml2.config import IdPConfig
from saml2.server import Server
from satosa.frontends.saml2 import SamlFrontend
from urllib.parse import urlparse

LOGGER = logging.getLogger(__name__)


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
