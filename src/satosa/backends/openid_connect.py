from datetime import datetime
from urllib.parse import urlparse
import logging

from jwkest.jws import alg2keytype

from oic.oauth2 import rndstr

from oic.utils.authn.authn_context import UNSPECIFIED
from oic.utils.keyio import KeyJar
from oic.utils.http_util import Redirect
from oic.exception import MissingAttribute
from oic import oic
from oic.oauth2 import ErrorResponse
from oic.oic import ProviderConfigurationResponse, AuthorizationResponse
from oic.oic import RegistrationResponse

from oic.oic import AuthorizationRequest

from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from satosa.backends.base import BackendModule
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHashType
from satosa.state import State

__author__ = 'danielevertsson'

logger = logging.getLogger(__name__)


def get_id_token(client, state):
    return client.grant[state].get_id_token()


# Produce a JWS, a signed JWT, containing a previously received ID token
def id_token_as_signed_jwt(client, id_token, alg="RS256"):
    ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    _signed_jwt = id_token.to_jwt(key=ckey, algorithm=alg)
    return _signed_jwt


class MissingUrlPath(Exception):
    pass


class StateKeys:
    OP = "op"
    NONCE = "nonce"
    TOKEN_ENDPOINT = "token_endpoint"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"
    JWKS_URI = "remote_keys_sources"
    USERINFO_ENDPOINT = "userinfo_endpoint"


class OpenIdBackend(BackendModule):
    def __init__(self, auth_callback_func, config):
        super(OpenIdBackend, self).__init__(auth_callback_func)
        self.auth_callback_func = auth_callback_func
        self.config = config
        self.oidc_clients = OIDCClients(self.config)

    def get_oidc_clients(self):
        return self.oidc_clients

    def start_auth(self, context, request_info, state):
        oidc_clients = self.get_oidc_clients()
        try:
            client_key = next(iter(oidc_clients.client.keys()))
        except:
            client_key=False

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
        state_data = {
            StateKeys.OP: client_key,
            StateKeys.NONCE: nonce,
            StateKeys.TOKEN_ENDPOINT: client.token_endpoint,
            StateKeys.CLIENT_ID: client.client_id,
            StateKeys.CLIENT_SECRET: client.client_secret,
            StateKeys.JWKS_URI: jwks_uri,
            StateKeys.USERINFO_ENDPOINT: client.userinfo_endpoint,
        }

        state.add(self.config.STATE_ID, state_data)
        try:
            resp = client.create_authn_request(
                state.urlstate(self.config.STATE_ENCRYPTION_KEY),
                nonce,
                self.config.ACR_VALUES
            )
        except Exception:
            raise
        else:
            return resp

    # TODO not done yet. Info needs to be sent through state
    def restore_state(self, state):
        oidc_clients = self.get_oidc_clients()
        client = oidc_clients.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                              behaviour=self.config.CLIENTS[""]["behaviour"],
                                              verify_ssl=self.config.VERIFY_SSL)
        client.token_endpoint = state[StateKeys.TOKEN_ENDPOINT]
        client = self.fetch_op_keys(client, state)
        self.load_client_registration_info(client, state)
        client.userinfo_endpoint = state[StateKeys.USERINFO_ENDPOINT]
        return client

    def load_client_registration_info(self, client, state):
        val = {
            "client_registration": {
                "client_id": state[StateKeys.CLIENT_ID],
                "client_secret": state[StateKeys.CLIENT_SECRET],
                "redirect_uris": [self.config.CLIENTS[""]["client_info"]["redirect_uris"][0]]
            }
        }
        client.store_registration_info(RegistrationResponse(
            **val["client_registration"]))

    def fetch_op_keys(self, client, state):
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
        url = urlparse(endpoint)
        if not url.path:
            raise MissingUrlPath()
        url_map.append(("%s?(.+?)" % url.path[1:], (function, binding)))
        url_map.append(("%s" % url.path[1:], (function, binding)))
        return url_map

    def redirect_endpoint(self, context, *args):
        oidc_clients = self.get_oidc_clients()
        state = State(context.request['state'], self.config.STATE_ENCRYPTION_KEY)
        backend_state = state.get(self.config.STATE_ID)

        try:
            client = oidc_clients.client[backend_state["op"]]
        except KeyError:
            client = self.restore_state(backend_state)

        result = client.callback(context.request)
        return self.auth_callback_func(context,
                                       self._translate_response(
                                           result,
                                           client.authorization_endpoint,
                                           self.get_subject_type(client),
                                       ),
                                       state)

    def get_subject_type(self, client):
        try:
            #oidc_clients.config.CLIENTS[""]["client_info"]["subject_type"]
            supported = client.provider_info["subject_types_supported"]
            return supported[0]
        except:
            pass
        return "public"

    def _translate_response(self, response, issuer, subject_type):
        oidc_clients = self.get_oidc_clients()
        subject_type = subject_type
        auth_info = AuthenticationInformation(UNSPECIFIED, str(datetime.now()), issuer)

        internal_resp = InternalResponse(
            self.name_format_to_hash_type(subject_type),
            auth_info=auth_info
        )
        internal_resp.add_oidc_attributes(response)
        internal_resp.user_id = response["sub"]
        return internal_resp

    def name_format_to_hash_type(self, name_format):
        if name_format == "public":
            return UserIdHashType.public
        elif name_format == "pairwise":
            return UserIdHashType.pairwise
        return None


class OIDCError(Exception):
    pass


class Client(oic.Client):
    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, behaviour=None):
        oic.Client.__init__(self, client_id, ca_certs, client_prefs,
                            client_authn_method, keyjar, verify_ssl)
        if behaviour:
            self.behaviour = behaviour

    def create_authn_request(self, state, nonce, acr_value=None, **kwargs):
        request_args = self.setup_authn_request_args(acr_value, kwargs, state, nonce)

        cis = self.construct_AuthorizationRequest(request_args=request_args)
        logger.debug("request: %s" % cis)

        url, body, ht_args, cis = self.uri_and_body(AuthorizationRequest, cis,
                                                    method="GET",
                                                    request_args=request_args)

        logger.debug("body: %s" % body)
        logger.info("URL: %s" % url)
        logger.debug("ht_args: %s" % ht_args)

        resp = Redirect(str(url))
        if ht_args:
            resp.headers.extend([(a, b) for a, b in ht_args.items()])
        logger.debug("resp_headers: %s" % resp.headers)
        return resp

    def setup_authn_request_args(self, acr_value, kwargs, state, nonce):
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

    def callback(self, response):
        """
        This is the method that should be called when an AuthN response has been
        received from the OP.

        :param response: The URL returned by the OP
        :return:
        """
        authresp = self.parse_response(AuthorizationResponse, response,
                                       sformat="dict", keyjar=self.keyjar)

        if isinstance(authresp, ErrorResponse):
            if authresp["error"] == "login_required":
                return self.create_authn_request(authresp["state"])
            else:
                return OIDCError("Access denied")
        try:
            if authresp["id_token"] != authresp["state"]:
                return OIDCError("Received nonce not the same as expected.")
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
                logger.error("%s" % err)
                raise

            if isinstance(atresp, ErrorResponse):
                raise OIDCError("Invalid response %s." % atresp["error"])

        kwargs = {}
        try:
            kwargs = {"method": self.userinfo_request_method}
        except AttributeError:
            kwargs = {}

        inforesp = self.do_user_info_request(state=authresp["state"], **kwargs)

        if isinstance(inforesp, ErrorResponse):
            raise OIDCError("Invalid response %s." % inforesp["error"])

        userinfo = inforesp.to_dict()

        logger.debug("UserInfo: %s" % inforesp)

        return userinfo


class OIDCClients(object):
    def __init__(self, config):
        """

        :param config: Imported configuration module
        :return:
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

        :param userid: An identifier of the user
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
        :param item:
        :return:
        """
        try:
            return self.client[item]
        except KeyError:
            return self.dynamic_client(item)

    def keys(self):
        return list(self.client.keys())
