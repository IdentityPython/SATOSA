"""
A OpenID Connect frontend module for the satosa proxy
"""
import json
import logging
from urllib.parse import urlencode, urlparse

from jwkest.jwk import rsa_load, RSAKey
from oic.oic import scope2claims
from oic.oic.message import (AuthorizationRequest, AuthorizationErrorResponse, TokenErrorResponse,
                             UserInfoErrorResponse)
from oic.oic.provider import RegistrationEndpoint, AuthorizationEndpoint, TokenEndpoint, UserinfoEndpoint
from pyop.access_token import AccessToken
from pyop.authz_state import AuthorizationState
from pyop.exceptions import (InvalidAuthenticationRequest, InvalidClientRegistrationRequest,
                             InvalidClientAuthentication, OAuthError, BearerTokenError, InvalidAccessToken)
from pyop.provider import Provider
from pyop.storage import MongoWrapper
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo
from pyop.util import should_fragment_encode

from .base import FrontendModule
from ..internal_data import InternalRequest
from ..internal_data import UserIdHashType
from ..logging_util import satosa_logging
from ..response import BadRequest, Created
from ..response import SeeOther, Response
from ..response import Unauthorized
from ..util import rndstr

logger = logging.getLogger(__name__)


def oidc_subject_type_to_hash_type(subject_type):
    if subject_type == "public":
        return UserIdHashType.public

    return UserIdHashType.pairwise


class OpenIDConnectFrontend(FrontendModule):
    """
    A OpenID Connect frontend module
    """

    def __init__(self, auth_req_callback_func, internal_attributes, conf, base_url, name):
        self._validate_config(conf)
        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)

        self.config = conf
        self.signing_key = RSAKey(key=rsa_load(conf["signing_key_path"]), use="sig", alg="RS256")

    def _create_provider(self, endpoint_baseurl):
        response_types_supported = self.config["provider"].get("response_types_supported", ["id_token"])
        subject_types_supported = self.config["provider"].get("subject_types_supported", ["pairwise"])
        scopes_supported = self.config["provider"].get("scopes_supported", ["openid"])
        capabilities = {
            "issuer": self.base_url,
            "authorization_endpoint": "{}/{}".format(endpoint_baseurl, AuthorizationEndpoint.url),
            "jwks_uri": "{}/jwks".format(endpoint_baseurl),
            "response_types_supported": response_types_supported,
            "id_token_signing_alg_values_supported": [self.signing_key.alg],
            "response_modes_supported": ["fragment", "query"],
            "subject_types_supported": subject_types_supported,
            "claim_types_supported": ["normal"],
            "claims_parameter_supported": True,
            "claims_supported": [attribute_map["openid"][0]
                                 for attribute_map in self.internal_attributes["attributes"].values()
                                 if "openid" in attribute_map],
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "scopes_supported": scopes_supported
        }

        if self.config["provider"].get("client_registration_supported", False):
            capabilities["registration_endpoint"] = "{}/{}".format(endpoint_baseurl, RegistrationEndpoint.url)

        authz_state = self._init_authorization_state()
        db_uri = self.config.get("db_uri")
        cdb = MongoWrapper(db_uri, "satosa", "clients") if db_uri else {}
        self.user_db = MongoWrapper(db_uri, "satosa", "authz_codes") if db_uri else {}
        self.provider = Provider(self.signing_key, capabilities, authz_state, cdb, Userinfo(self.user_db))

    def _init_authorization_state(self):
        sub_hash_salt = self.config.get("sub_hash_salt", rndstr(16))
        db_uri = self.config.get("db_uri")
        if db_uri:
            authz_code_db = MongoWrapper(db_uri, "satosa", "authz_codes")
            access_token_db = MongoWrapper(db_uri, "satosa", "access_tokens")
            refresh_token_db = MongoWrapper(db_uri, "satosa", "refresh_tokens")
            sub_db = MongoWrapper(db_uri, "satosa", "subject_identifiers")
        else:
            authz_code_db = None
            access_token_db = None
            refresh_token_db = None
            sub_db = None

        token_lifetimes = {k: self.config["provider"][k] for k in ["authorization_code_lifetime",
                                                                   "access_token_lifetime",
                                                                   "refresh_token_lifetime",
                                                                   "refresh_token_threshold"]
                           if k in self.config["provider"]}
        return AuthorizationState(HashBasedSubjectIdentifierFactory(sub_hash_salt), authz_code_db, access_token_db,
                                  refresh_token_db, sub_db, **token_lifetimes)

    def handle_authn_response(self, context, internal_resp, extra_id_token_claims=None):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :rtype oic.utils.http_util.Response
        """

        auth_req = self._get_authn_request_from_state(context.state)

        attributes = self.converter.from_internal("openid", internal_resp.attributes)
        self.user_db[internal_resp.user_id] = {k: v[0] for k, v in attributes.items()}
        auth_resp = self.provider.authorize(auth_req, internal_resp.user_id, extra_id_token_claims)

        del context.state[self.name]
        http_response = auth_resp.request(auth_req["redirect_uri"], should_fragment_encode(auth_req))
        return SeeOther(http_response)

    def handle_backend_error(self, exception):
        """
        See super class satosa.frontends.base.FrontendModule
        :type exception: satosa.exception.SATOSAError
        :rtype: oic.utils.http_util.Response
        """
        auth_req = self._get_authn_request_from_state(exception.state)
        # If the client sent us a state parameter, we should reflect it back according to the spec
        if 'state' in auth_req: 
            error_resp = AuthorizationErrorResponse(error="access_denied",
                                                    error_description=exception.message,
                                                    state=auth_req['state'])
        else:                                           
            error_resp = AuthorizationErrorResponse(error="access_denied", 
                                                    error_description=exception.message)
        satosa_logging(logger, logging.DEBUG, exception.message, exception.state)
        return SeeOther(error_resp.request(auth_req["redirect_uri"], should_fragment_encode(auth_req)))

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        backend_name = None
        if len(backend_names) != 1:
            # only supports one backend since there currently is no way to publish multiple authorization endpoints
            # in configuration information and there is no other standard way of authorization_endpoint discovery
            # similar to SAML entity discovery
            # this can be circumvented with a custom RequestMicroService which handles the routing based on something
            # in the authentication request
            logger.warn("More than one backend is configured, make sure to provide a custom routing micro service to "
                        "determine which backend should be used per request.")
        else:
            backend_name = backend_names[0]

        endpoint_baseurl = "{}/{}".format(self.base_url, self.name)
        self._create_provider(endpoint_baseurl)

        provider_config = ("^.well-known/openid-configuration$", self.provider_config)
        jwks_uri = ("^{}/jwks$".format(self.name), self.jwks)

        if backend_name:
            # if there is only one backend, include its name in the path so the default routing can work
            auth_endpoint = "{}/{}/{}/{}".format(self.base_url, backend_name, self.name, AuthorizationEndpoint.url)
            self.provider.configuration_information["authorization_endpoint"] = auth_endpoint
            auth_path = urlparse(auth_endpoint).path.lstrip("/")
        else:
            auth_path = "{}/{}".format(self.name, AuthorizationEndpoint.url)
        authentication = ("^{}$".format(auth_path), self.handle_authn_request)
        url_map = [provider_config, jwks_uri, authentication]

        if any("code" in v for v in self.provider.configuration_information["response_types_supported"]):
            self.provider.configuration_information["token_endpoint"] = "{}/{}".format(endpoint_baseurl,
                                                                                       TokenEndpoint.url)
            token_endpoint = ("^{}/{}".format(self.name, TokenEndpoint.url), self.token_endpoint)
            url_map.append(token_endpoint)

            self.provider.configuration_information["userinfo_endpoint"] = "{}/{}".format(endpoint_baseurl,
                                                                                          UserinfoEndpoint.url)
            userinfo_endpoint = ("^{}/{}".format(self.name, UserinfoEndpoint.url), self.userinfo_endpoint)
            url_map.append(userinfo_endpoint)
        if "registration_endpoint" in self.provider.configuration_information:
            client_registration = ("^{}/{}".format(self.name, RegistrationEndpoint.url), self.client_registration)
            url_map.append(client_registration)

        return url_map

    def _validate_config(self, config):
        """
        Validates that all necessary config parameters are specified.
        :type config: dict[str, dict[str, Any] | str]
        :param config: the module config
        """
        if config is None:
            raise ValueError("OIDCFrontend conf can't be 'None'.")

        for k in {"signing_key_path", "provider"}:
            if k not in config:
                raise ValueError("Missing configuration parameter '{}' for OpenID Connect frontend.".format(k))

    def _get_authn_request_from_state(self, state):
        """
        Extract the clietns request stoed in the SATOSA state.
        :type state: satosa.state.State
        :rtype: oic.oic.message.AuthorizationRequest

        :param state: the current state
        :return: the parsed authentication request
        """
        return AuthorizationRequest().deserialize(state[self.name]["oidc_request"])

    def client_registration(self, context):
        """
        Handle the OIDC dynamic client registration.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        try:
            resp = self.provider.handle_client_registration_request(json.dumps(context.request))
            return Created(resp.to_json(), content="application/json")
        except InvalidClientRegistrationRequest as e:
            return BadRequest(e.to_json(), content="application/json")

    def provider_config(self, context):
        """
        Construct the provider configuration information (served at /.well-known/openid-configuration).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        return Response(self.provider.provider_configuration.to_json(), content="application/json")

    def _get_approved_attributes(self, provider_supported_claims, authn_req):
        requested_claims = list(scope2claims(authn_req["scope"]).keys())
        if "claims" in authn_req:
            for k in ["id_token", "userinfo"]:
                if k in authn_req["claims"]:
                    requested_claims.extend(authn_req["claims"][k].keys())
        return set(provider_supported_claims).intersection(set(requested_claims))

    def _handle_authn_request(self, context):
        """
        Parse and verify the authentication request into an internal request.
        :type context: satosa.context.Context
        :rtype: internal_data.InternalRequest

        :param context: the current context
        :return: the internal request
        """
        request = urlencode(context.request)
        satosa_logging(logger, logging.DEBUG, "Authn req from client: {}".format(request),
                       context.state)

        try:
            authn_req = self.provider.parse_authentication_request(request)
        except InvalidAuthenticationRequest as e:
            satosa_logging(logger, logging.ERROR, "Error in authn req: {}".format(str(e)),
                           context.state)
            error_url = e.to_error_url()

            if error_url:
                return SeeOther(error_url)
            else:
                return BadRequest("Something went wrong: {}".format(str(e)))

        client_id = authn_req["client_id"]
        context.state[self.name] = {"oidc_request": request}
        hash_type = oidc_subject_type_to_hash_type(self.provider.clients[client_id].get("subject_type", "pairwise"))
        client_name = self.provider.clients[client_id].get("client_name")
        if client_name:
            # TODO should process client names for all languages, see OIDC Registration, Section 2.1
            requester_name = [{"lang": "en", "text": client_name}]
        else:
            requester_name = None
        internal_req = InternalRequest(hash_type, client_id, requester_name)

        internal_req.approved_attributes = self.converter.to_internal_filter(
            "openid", self._get_approved_attributes(self.provider.configuration_information["claims_supported"],
                                                    authn_req))
        return internal_req

    def handle_authn_request(self, context):
        """
        Handle an authentication request and pass it on to the backend.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        internal_req = self._handle_authn_request(context)
        if not isinstance(internal_req, InternalRequest):
            return internal_req
        return self.auth_req_callback_func(context, internal_req)

    def jwks(self, context):
        """
        Construct the JWKS document (served at /jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        return Response(json.dumps(self.provider.jwks), content="application/json")

    def token_endpoint(self, context):
        """
        Handle token requests (served at /token).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        headers = {"Authorization": context.request_authorization}
        try:
            response = self.provider.handle_token_request(urlencode(context.request), headers)
            return Response(response.to_json(), content="application/json")
        except InvalidClientAuthentication as e:
            logger.debug('invalid client authentication at token endpoint', exc_info=True)
            error_resp = TokenErrorResponse(error='invalid_client', error_description=str(e))
            response = Unauthorized(error_resp.to_json(), headers=[("WWW-Authenticate", "Basic")],
                                    content="application/json")
            return response
        except OAuthError as e:
            logger.debug('invalid request: %s', str(e), exc_info=True)
            error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
            return BadRequest(error_resp.to_json(), content="application/json")

    def userinfo_endpoint(self, context):
        headers = {"Authorization": context.request_authorization}

        try:
            response = self.provider.handle_userinfo_request(urlencode(context.request), headers)
            return Response(response.to_json(), content="application/json")
        except (BearerTokenError, InvalidAccessToken) as e:
            error_resp = UserInfoErrorResponse(error='invalid_token', error_description=str(e))
            response = Unauthorized(error_resp.to_json(), headers=[("WWW-Authenticate", AccessToken.BEARER_TOKEN_TYPE)],
                                    content="application/json")
            return response
