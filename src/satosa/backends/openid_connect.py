"""
OIDC backend module.
"""
from datetime import datetime
from urllib.parse import urlparse
import logging

from oic.oauth2 import rndstr
from oic.utils.authn.authn_context import UNSPECIFIED
from oic.utils.keyio import KeyJar
from oic.exception import MissingAttribute
from oic import oic
from oic.oauth2 import ErrorResponse
from oic.oic import ProviderConfigurationResponse, AuthorizationResponse
from oic.oic import RegistrationResponse
from oic.oic import AuthorizationRequest

from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from satosa.exception import SATOSAAuthenticationError, SATOSAError
from satosa.logging_util import satosa_logging
from satosa.response import Redirect
from satosa.backends.base import BackendModule, get_metadata_desc_for_oidc_backend
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHashType, \
    DataConverter

__author__ = 'danielevertsson'

LOGGER = logging.getLogger(__name__)


class StateKeys:
    """
    Keys used in the SATOSA state
    """
    OP = "op"
    NONCE = "nonce"
    TOKEN_ENDPOINT = "token_endpoint"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"
    JWKS_URI = "remote_keys_sources"
    USERINFO_ENDPOINT = "userinfo_endpoint"
    STATE = "state"


class RpConfig(object):
    """
    OIDC connect configuration class for clients.
    """
    def __init__(self, config):
        self.CLIENTS = {
            config["authz_page"]: config["client"]
        }
        self.ACR_VALUES = config["acr_values"]
        self.VERIFY_SSL = config["verify_ssl"]
        self.OP_URL = config["op_url"]
        self.STATE_ID = config["state_id"]
        self.USER_ID_PARAMAS = None
        if "user_id_paramas" in config:
            self.USER_ID_PARAMAS = config["user_id_paramas"]

        self.CLIENTS[config["authz_page"]]["srv_discovery_url"] = self.OP_URL


class OpenIdBackend(BackendModule):
    """
    OIDC module
    """
    def __init__(self, auth_callback_func, internal_attributes, config):
        """
        OIDC backend module.
        :param auth_callback_func: Callback should be called by the module after the authorization
        in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        :param config: Configuration parameters for the module.

        :type auth_callback_func:
        (satosa.context.Context, satosa.internal_data.InternalResponse) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type config: dict[str, dict[str, str] | list[str]]
        """
        super(OpenIdBackend, self).__init__(auth_callback_func, internal_attributes)
        self.auth_callback_func = auth_callback_func
        self.config = RpConfig(config)
        self.oidc_backend_config = config
        self.oidc_clients = None
        self.converter = DataConverter(internal_attributes)

    def get_oidc_clients(self):
        """
        Creates an instance of the class that holds all oidc clients.

        :rtype: OIDCClients
        :return: Instance of OIDCClients class.
        """
        self.oidc_clients = OIDCClients(self.config)
        return self.oidc_clients

    def start_auth(self, context, request_info):
        """
        See super class method satosa.backends.base#start_auth
        :type context: satosa.context.Context
        :type request_info: satosa.internal_data.InternalRequest
        """

        oidc_clients = self.get_oidc_clients()
        try:
            client_key = next(iter(oidc_clients.client.keys()))
        except:
            client_key = False

        if client_key:
            client = oidc_clients[client_key]
        else:
            client = oidc_clients.dynamic_client(self.config.OP_URL)
            client_key = client.provider_info["issuer"]

        jwks_uri = ""
        try:
            for issuer in client.keyjar.issuer_keys:
                if issuer != "":
                    jwks_uri = client.keyjar.issuer_keys[issuer][0].source
        except:
            pass

        nonce = rndstr()
        oidc_state = rndstr()
        state_data = {
            StateKeys.OP: client_key,
            StateKeys.NONCE: nonce,
            StateKeys.STATE: oidc_state
        }

        if "client_registration" not in self.config.CLIENTS[client_key]:
            save_state_dict = {
                StateKeys.TOKEN_ENDPOINT: client.token_endpoint,
                StateKeys.CLIENT_ID: client.client_id,
                StateKeys.CLIENT_SECRET: client.client_secret,
                StateKeys.JWKS_URI: jwks_uri,
                StateKeys.USERINFO_ENDPOINT: client.userinfo_endpoint
            }
        else:
            save_state_dict = {}
        state_data.update(save_state_dict)

        context.state.add(self.config.STATE_ID, state_data)
        try:
            resp = client.create_authn_request(
                context.state,
                oidc_state,
                nonce,
                self.config.ACR_VALUES
            )
        except Exception:
            raise
        else:
            return resp

    def restore_state(self, state):
        """
        Restores the satosa state after a redirect.
        :type state: dict[str, str]
        :rtype: Client

        :param state: The data saved on the state.
        :return: A oidc client.
        """
        oidc_clients = self.get_oidc_clients()
        if state["op"] in oidc_clients.client:
            key = state["op"]
        else:
            key = ""
        if "client_registration" not in self.config.CLIENTS[key]:
            client = oidc_clients.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                             behaviour=self.config.CLIENTS[key]["behaviour"],
                                             verify_ssl=self.config.VERIFY_SSL)
            client.token_endpoint = state[StateKeys.TOKEN_ENDPOINT]
            client = self.fetch_op_keys(client, state)
            self.load_client_registration_info(client, state, key)
            client.userinfo_endpoint = state[StateKeys.USERINFO_ENDPOINT]
            client.authorization_endpoint = oidc_clients[key].authorization_endpoint
        else:
            return oidc_clients[key]
        return client

    def load_client_registration_info(self, client, state, key):
        """
        Loads client registration information into the oidc client.
        :type client: Client
        :type state: dict[str, str]
        :type key: str

        :param client: oidc client
        :param state: A dictionary with all state values for the backend module.
        :param key: oidc client key
        """
        try:
            redirect_uris = self.config.CLIENTS[key]["client_info"]["redirect_uris"]
        except:
            redirect_uris = self.config.CLIENTS[key]["client_registration"]["redirect_uris"]
        val = {
            "client_registration": {
                "client_id": state[StateKeys.CLIENT_ID],
                "client_secret": state[StateKeys.CLIENT_SECRET],
                "redirect_uris": redirect_uris
            }
        }
        client.store_registration_info(RegistrationResponse(
            **val["client_registration"]))

    def fetch_op_keys(self, client, state):
        """
        Fetch op keys

        :type client: Client
        :type state: dict[str, str]

        :param client: oidc client
        :param state: A dictionary with all state values for the backend module.
        :return: oidc client with op keys.
        """
        client.keyjar = KeyJar(verify_ssl=self.config.VERIFY_SSL)
        pcr = ProviderConfigurationResponse()
        pcr['jwks_uri'] = state[StateKeys.JWKS_URI]
        client.handle_provider_config(pcr, self.config.OP_URL)
        for issuer, keybundle_list in client.keyjar.issuer_keys.items():
            for kb in keybundle_list:
                if kb.remote:
                    kb.do_remote()
        return client

    def register_endpoints(self):
        """
        Creates a list of all the endpoints this backend module needs to listen to. In this case
        it's the authentication response from the underlying OP that is redirected from the OP to
        the proxy.
        :rtype:
        list[(str, (satosa.context.Context) -> satosa.response.Response)]
        :return: A list that can be used to map the request to SATOSA to this endpoint.
        """
        url_map = []

        for key in self.config.CLIENTS:
            try:
                redirect_uris = self.config.CLIENTS[key]["client_info"]["redirect_uris"]
            except:
                try:
                    redirect_uris = self.config.CLIENTS[key]["client_registration"]["redirect_uris"]
                except:
                    redirect_uris = []
            for uri in redirect_uris:
                url_map = self._add_endpoint_to_url_map(uri, url_map, self.redirect_endpoint)

        return url_map

    def _add_endpoint_to_url_map(self, endpoint, url_map, function, binding=None):
        """
        Adds a url endpoints and function to call when the requested url matches the endpoint.
        :type endpoint: str
        :type url_map: list[str]
        :type function: (satosa.context.Context, Any) -> satosa.response.Response
        :type binding: str

        :param endpoint: An ulr endpoint.
        :param url_map: The map to add endpoints to.
        :param function: The functoin to call if it's a match.
        :param binding: This binding value will be sent to the function function.
        :return:
        """
        url = urlparse(endpoint)
        if not url.path:
            raise SATOSAError("Missing url path")
        url_map.append(("%s?(.+?)" % url.path[1:], (function, binding)))
        url_map.append(("%s" % url.path[1:], (function, binding)))
        return url_map

    def redirect_endpoint(self, context, *args):
        """
        Handles the authentication response from the OP.
        :type context: satosa.context.Context
        :type args: Any
        :rtype: satosa.response.Response

        :param context: SATOSA context
        :param args: None
        :return:
        """
        state = context.state
        backend_state = state.get(self.config.STATE_ID)
        if backend_state["state"] != context.request["state"]:
            satosa_logging(LOGGER, logging.DEBUG,
                           "Missing or invalid state in authn response for state: %s" %
                           backend_state,
                           state)
            raise SATOSAAuthenticationError(state, "Missing or invalid state in authn response")
        client = self.restore_state(backend_state)
        result = client.callback(context.request, state, backend_state)
        context.state.remove(self.config.STATE_ID)
        return self.auth_callback_func(context,
                                       self._translate_response(
                                           result,
                                           client.authorization_endpoint,
                                           self.get_subject_type(client),
                                       ))

    def get_subject_type(self, client):
        """
        Supported subject types by the OP.
        :type client: Client
        :param client: oidc client
        :return: Supported subject type
        """
        try:
            supported = client.provider_info["subject_types_supported"]
            return supported[0]
        except:
            pass
        return "public"

    def _translate_response(self, response, issuer, subject_type):
        """
        Translates oidc response to SATOSA internal response.
        :type response: dict[str, str]
        :type issuer: str
        :type subject_type: str
        :rtype: InternalResponse

        :param response: Dictioary with attribute name as key.
        :param issuer: The oidc op that gave the repsonse.
        :param subject_type: public or pairwise according to oidc standard.
        :return: A SATOSA internal response.
        """
        oidc_clients = self.get_oidc_clients()
        subject_type = subject_type
        auth_info = AuthenticationInformation(UNSPECIFIED, str(datetime.now()), issuer)

        internal_resp = InternalResponse(
            auth_info=auth_info
        )

        internal_resp.add_attributes(self.converter.to_internal("openid", response))
        internal_resp.set_user_id(response["sub"])
        if self.config.USER_ID_PARAMAS:
            user_id = ""
            for param in self.config.USER_ID_PARAMAS:
                try:
                    user_id += response[param]
                except Exception as error:
                    raise SATOSAAuthenticationError from error
            internal_resp.set_user_id(user_id)

        return internal_resp

    def name_format_to_hash_type(self, name_format):
        """
        Maps a hashtype from oidc public or pairwise.
        :type name_format: str
        :param name_format: Can be public or pairwise.
        :return: UserIdHashType
        """
        if name_format == "public":
            return UserIdHashType.public
        elif name_format == "pairwise":
            return UserIdHashType.pairwise
        return None

    def get_metadata_desc(self):
        """
        See super class satosa.backends.base.BackendModule#get_metadata_desc
        :rtype: satosa.metadata_creation.description.MetadataDescription
        """
        return get_metadata_desc_for_oidc_backend(self.oidc_backend_config)


class Client(oic.Client):
    """
    OIDC client
    """
    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, behaviour=None):
        """
        See class oic.Client
        :param behaviour: Can contains the keys "resonse_type" or "scope".
        :type behaviour: dict[str, str | list[str]]
        :return:
        """
        oic.Client.__init__(self, client_id, ca_certs, client_prefs,
                            client_authn_method, keyjar, verify_ssl)
        if behaviour:
            self.behaviour = behaviour

    def create_authn_request(self, state, oidc_state, nonce, acr_value=None, **kwargs):
        """
        Creates an oidc authentication request.
        :type state: satosa.state.State
        :type oidc_state: str
        :type nonce: str
        :type acr_value: list[str]
        :type kwargs: Any
        :rtype: satosa.response.Redirect

        :param state: Module state
        :param oidc_state: OIDC state
        :param nonce: A nonce
        :param acr_value: Authentication type
        :param kwargs: Whatever
        :return: A redirect to the OP
        """
        request_args = self.setup_authn_request_args(acr_value, kwargs, oidc_state, nonce)

        cis = self.construct_AuthorizationRequest(request_args=request_args)
        satosa_logging(LOGGER, logging.DEBUG, "request: %s" % cis, state)

        url, body, ht_args, cis = self.uri_and_body(AuthorizationRequest, cis,
                                                    method="GET",
                                                    request_args=request_args)

        satosa_logging(LOGGER, logging.DEBUG, "body: %s" % body, state)
        satosa_logging(LOGGER, logging.INFO, "URL: %s" % url, state)
        satosa_logging(LOGGER, logging.DEBUG, "ht_args: %s" % ht_args, state)

        resp = Redirect(str(url))
        if ht_args:
            resp.headers.extend([(a, b) for a, b in ht_args.items()])
        satosa_logging(LOGGER, logging.DEBUG, "resp_headers: %s" % resp.headers, state)
        return resp

    def setup_authn_request_args(self, acr_value, kwargs, state, nonce):
        """
        Creates request arguments needed to create an oidc authentication request.

        :type state: str
        :type nonce: str
        :type acr_value: list[str]
        :type kwargs: Any
        :rtype: dict[str, str | list[str]]

        :param acr_value: Authentication type
        :param kwargs: whatever
        :param state: OIDC state
        :param nonce: A nonce
        :return:
        """
        request_args = {
            "response_type": self.behaviour["response_type"],
            "scope": self.behaviour["scope"],
            "state": state,
            "nonce": nonce,
            "redirect_uri": self.registration_response["redirect_uris"][0]
        }
        if acr_value is not None:
            request_args["acr_values"] = acr_value
        request_args.update(kwargs)
        return request_args

    def callback(self, response, state, backend_state):
        """
        This is the method that should be called when an AuthN response has been
        received from the OP.
        :type response: dict[str, str]
        :type state: satosa.sate.State
        :type backend_state: dict[str, str]
        :rtype: satosa.response.Response

        :param response: The response parameters from the OP.
        :param state: A SATOSA state.
        :param backend_state: The state data for this backend module.
        :return:
        """
        authresp = self.parse_response(AuthorizationResponse, response,
                                       sformat="dict", keyjar=self.keyjar)

        if isinstance(authresp, ErrorResponse):
            if authresp["error"] == "login_required":
                satosa_logging(LOGGER, logging.WARN, "Access denied for state: %s" % backend_state,
                               state)
                raise SATOSAAuthenticationError(state, "Access denied")
            else:
                satosa_logging(LOGGER, logging.DEBUG, "Access denied for state: %s" % backend_state,
                               state)
                raise SATOSAAuthenticationError(state, "Access denied")
        try:
            if authresp["id_token"] != backend_state["nonce"]:
                satosa_logging(LOGGER, logging.DEBUG,
                               "Invalid nonce. for state: %s" % backend_state, state)
                raise SATOSAAuthenticationError(state, "Invalid nonce")
            self.id_token[authresp["state"]] = authresp["id_token"]
        except KeyError:
            pass

        if self.behaviour["response_type"] == "code":
            # get the access token
            try:
                args = {
                    "code": authresp["code"],
                    "redirect_uri": self.registration_response[
                        "redirect_uris"][0],
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }

                atresp = self.do_access_token_request(
                    scope="openid", state=authresp["state"], request_args=args,
                    authn_method=self.registration_response["token_endpoint_auth_method"])
            except Exception as err:
                satosa_logging(LOGGER, logging.ERROR, "%s" % err, state, exc_info=True)
                raise

            if isinstance(atresp, ErrorResponse):
                msg = "Invalid response %s." % atresp["error"]
                satosa_logging(LOGGER, logging.ERROR, msg, state)
                raise SATOSAAuthenticationError(state, msg)

        kwargs = {}
        try:
            kwargs = {"method": self.userinfo_request_method}
        except AttributeError:
            pass

        inforesp = self.do_user_info_request(state=authresp["state"], **kwargs)

        if isinstance(inforesp, ErrorResponse):
            msg = "Invalid response %s." % inforesp["error"]
            satosa_logging(LOGGER, logging.ERROR, msg, state)
            raise SATOSAAuthenticationError(state, "Invalid response %s." % inforesp["error"])

        userinfo = inforesp.to_dict()

        satosa_logging(LOGGER, logging.DEBUG, "UserInfo: %s" % inforesp, state)

        return userinfo


class OIDCClients(object):
    """
    Holds all oidc clients.
    """
    def __init__(self, config):
        """
        :type: RpConfig
        :param config: Imported configuration module
        """
        self.client = {}
        self.client_cls = Client
        self.config = config

        for key, val in config.CLIENTS.items():
            if key == "":
                continue
            else:
                self.client[key] = self.create_client(**val)

    def create_client(self, userid="", **kwargs):
        """
        Do an instantiation of a client instance
        :type userid: str
        :type kwargs: any
        :rtype: Client
        :param userid: An identifier of the user. In this case OP base url.
        :param: Keyword arguments
            Keys are ["srv_discovery_url", "client_info", "client_registration",
            "provider_info"]
        :return: client instance
        """

        _key_set = set(list(kwargs.keys()))
        args = {}
        for param in ["verify_ssl"]:
            try:
                args[param] = kwargs[param]
            except KeyError:
                pass
            else:
                _key_set.discard(param)

        client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                 behaviour=kwargs["behaviour"], verify_ssl=self.config.VERIFY_SSL,
                                 **args)

        try:
            client.userinfo_request_method = kwargs["userinfo_request_method"]
        except KeyError:
            pass
        else:
            _key_set.discard("userinfo_request_method")

        # The behaviour parameter is not significant for the election process
        _key_set.discard("behaviour")
        for param in ["allow"]:
            try:
                setattr(client, param, kwargs[param])
            except KeyError:
                pass
            else:
                _key_set.discard(param)

        if _key_set == {"client_info"}:  # Everything dynamic
            # There has to be a userid
            if not userid:
                raise MissingAttribute("Missing userid specification")

            # Find the service that provides information about the OP
            issuer = client.wf.discovery_query(userid)
            # Gather OP information
            _ = client.provider_config(issuer)
            # register the client
            _ = client.register(client.provider_info["registration_endpoint"],
                                **kwargs["client_info"])
        elif _key_set == {"client_info", "srv_discovery_url"}:
            # Ship the webfinger part
            # Gather OP information
            _ = client.provider_config(kwargs["srv_discovery_url"])
            # register the client
            _ = client.register(client.provider_info["registration_endpoint"],
                                **kwargs["client_info"])
        elif _key_set == {"provider_info", "client_info"}:
            client.handle_provider_config(
                ProviderConfigurationResponse(**kwargs["provider_info"]),
                kwargs["provider_info"]["issuer"])
            _ = client.register(client.provider_info["registration_endpoint"],
                                **kwargs["client_info"])
        elif _key_set == {"provider_info", "client_registration"}:
            client.handle_provider_config(
                ProviderConfigurationResponse(**kwargs["provider_info"]),
                kwargs["provider_info"]["issuer"])
            client.store_registration_info(RegistrationResponse(
                **kwargs["client_registration"]))
        elif _key_set == {"srv_discovery_url", "client_registration"}:
            _ = client.provider_config(kwargs["srv_discovery_url"])
            client.store_registration_info(RegistrationResponse(
                **kwargs["client_registration"]))
        else:
            raise Exception("Configuration error ?")

        return client

    def dynamic_client(self, userid):
        """
        Creates a new dynamic client.
        :type userid: str
        :rtype: Client
        :param userid: URL for the OP.
        :return: oidc client
        """
        client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                 verify_ssl=self.config.VERIFY_SSL)

        issuer = client.wf.discovery_query(userid)
        if issuer in self.client:
            return self.client[issuer]
        else:
            # Gather OP information
            _pcr = client.provider_config(issuer)
            # register the client
            _ = client.register(_pcr["registration_endpoint"],
                                **self.config.CLIENTS[""]["client_info"])
            try:
                client.behaviour.update(**self.config.CLIENTS[""]["behaviour"])
            except KeyError:
                pass

            self.client[issuer] = client
            return client

    def __getitem__(self, item):
        """
        Given a service or user identifier return a suitable client
        :type: item: str
        :param item: oidc client key
        :return: A oidc client.
        """
        try:
            return self.client[item]
        except KeyError:
            return self.dynamic_client(item)

    def keys(self):
        """
        :return: A list with keys.
        """
        return list(self.client.keys())
