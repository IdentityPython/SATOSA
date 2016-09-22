"""
The SATOSA main module
"""
import json
import logging
from uuid import uuid4

from satosa.micro_services import consent
from .context import Context
from .exception import SATOSAConfigurationError
from .exception import SATOSAError, SATOSAAuthenticationError, SATOSAUnknownError
from .internal_data import UserIdHasher
from .logging_util import satosa_logging
from .micro_services.account_linking import AccountLinking
from .micro_services.consent import Consent
from .plugin_loader import load_backends, load_frontends
from .plugin_loader import load_request_microservices, load_response_microservices
from .routing import ModuleRouter, SATOSANoBoundEndpointError
from .state import cookie_to_state, SATOSAStateError, State, state_to_cookie

logger = logging.getLogger(__name__)

STATE_KEY = "SATOSA_BASE"


class SATOSABase(object):
    """
    Base class for a satosa proxy server.
    Does not contain any server parts.
    """

    def __init__(self, config):
        """
        Creates a satosa proxy base

        :type config: satosa.satosa_config.SATOSAConfig
        :param config: satosa proxy config
        """
        self.config = config
        logger.info("Loading backend modules...")
        backends = load_backends(self.config, self._auth_resp_callback_func,
                                 self.config["INTERNAL_ATTRIBUTES"])
        logger.info("Loading frontend modules...")
        frontends = load_frontends(self.config, self._auth_req_callback_func,
                                   self.config["INTERNAL_ATTRIBUTES"])

        self.response_micro_services = []
        self.request_micro_services = []
        logger.info("Loading micro services...")
        if "MICRO_SERVICES" in self.config:
            self.request_micro_services.extend(load_request_microservices(self.config.get("CUSTOM_PLUGIN_MODULE_PATHS"),
                                                                          self.config["MICRO_SERVICES"],
                                                                          self.config["INTERNAL_ATTRIBUTES"],
                                                                          self.config["BASE"]))
            self._link_micro_services(self.request_micro_services, self._auth_req_finish)

            self.response_micro_services.extend(
                load_response_microservices(self.config.get("CUSTOM_PLUGIN_MODULE_PATHS"),
                                            self.config["MICRO_SERVICES"],
                                            self.config["INTERNAL_ATTRIBUTES"],
                                            self.config["BASE"]))
            self._verify_response_micro_services(self.response_micro_services)
            self._link_micro_services(self.response_micro_services, self._auth_resp_finish)

        self.module_router = ModuleRouter(frontends, backends,
                                          self.request_micro_services + self.response_micro_services)

    def _link_micro_services(self, micro_services, finisher):
        if not micro_services:
            return

        for i in range(len(micro_services) - 1):
            micro_services[i].next = micro_services[i + 1].process

        micro_services[-1].next = finisher

    def _verify_response_micro_services(self, response_micro_services):
        account_linking_index = next((i for i in range(len(response_micro_services))
                                      if isinstance(response_micro_services[i], AccountLinking)), -1)
        if account_linking_index > 0:
            raise SATOSAConfigurationError("Account linking must be configured first in the list of micro services")

        consent_index = next((i for i in range(len(response_micro_services))
                              if isinstance(response_micro_services[i], Consent)), -1)
        if consent_index != -1 and consent_index < len(response_micro_services) - 1:
            raise SATOSAConfigurationError("Consent must be configured last in the list of micro services")

    def _auth_req_callback_func(self, context, internal_request):
        """
        This function is called by a frontend module when an authorization request has been
        processed.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal_data.InternalRequest
        :rtype: satosa.response.Response

        :param context: The request context
        :param internal_request: request processed by the frontend

        :return: response
        """
        state = context.state
        state[STATE_KEY] = {"requester": internal_request.requester}
        # TODO consent module should manage any state it needs by itself
        context.state[consent.STATE_KEY] = {"filter": internal_request.approved_attributes or [],
                                            "requester_name": internal_request.requester_name}
        satosa_logging(logger, logging.INFO,
                       "Requesting provider: {}".format(internal_request.requester), state)

        UserIdHasher.save_state(internal_request, state)
        if self.request_micro_services:
            return self.request_micro_services[0].process(context, internal_request)

        return self._auth_req_finish(context, internal_request)

    def _auth_req_finish(self, context, internal_request):
        backend = self.module_router.backend_routing(context)
        context.request = None
        return backend.start_auth(context, internal_request)

    def _auth_resp_finish(self, context, internal_response):
        # re-hash user id since e.g. account linking micro service might have changed it
        user_id = UserIdHasher.hash_id(self.config["USER_ID_HASH_SALT"],
                                       internal_response.user_id,
                                       internal_response.requester,
                                       context.state)
        internal_response.user_id = user_id
        internal_response.user_id_hash_type = UserIdHasher.hash_type(context.state)
        user_id_to_attr = self.config["INTERNAL_ATTRIBUTES"].get("user_id_to_attr", None)
        if user_id_to_attr:
            internal_response.attributes[user_id_to_attr] = [internal_response.user_id]

        # Hash all attributes specified in INTERNAL_ATTRIBUTES["hash]
        hash_attributes = self.config["INTERNAL_ATTRIBUTES"].get("hash", [])
        internal_attributes = internal_response.attributes
        for attribute in hash_attributes:
            # hash all attribute values individually
            hashed_values = [UserIdHasher.hash_data(self.config["USER_ID_HASH_SALT"], v)
                             for v in internal_attributes[attribute]]
            internal_attributes[attribute] = hashed_values

        # remove all session state
        context.request = None
        context.state.delete = True
        frontend = self.module_router.frontend_routing(context)
        return frontend.handle_authn_response(context, internal_response)

    def _auth_resp_callback_func(self, context, internal_response):
        """
        This function is called by a backend module when the authorization is complete.

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :rtype: satosa.response.Response

        :param context: The request context
        :param internal_response: The authentication response
        :return: response
        """

        context.request = None
        internal_response.requester = context.state[STATE_KEY]["requester"]
        if "user_id_from_attrs" in self.config["INTERNAL_ATTRIBUTES"]:
            user_id = ["".join(internal_response.attributes[attr]) for attr in
                       self.config["INTERNAL_ATTRIBUTES"]["user_id_from_attrs"]]
            internal_response.user_id = "".join(user_id)
        # Hash the user id
        user_id = UserIdHasher.hash_data(self.config["USER_ID_HASH_SALT"], internal_response.user_id)
        internal_response.user_id = user_id

        if self.response_micro_services:
            return self.response_micro_services[0].process(context, internal_response)

        return self._auth_resp_finish(context, internal_response)

    def _handle_satosa_authentication_error(self, error):
        """
        Sends a response to the requester about the error

        :type error: satosa.exception.SATOSAAuthenticationError
        :rtype: satosa.response.Response

        :param error: The exception
        :return: response
        """
        context = Context()
        context.state = error.state
        frontend = self.module_router.frontend_routing(context)
        return frontend.handle_backend_error(error)

    def _run_bound_endpoint(self, context, spec):
        """

        :type context: satosa.context.Context
        :type spec: ((satosa.context.Context, Any) -> satosa.response.Response, Any) |
        (satosa.context.Context) -> satosa.response.Response

        :param context: The request context
        :param spec: bound endpoint function
        :return: response
        """
        try:
            return spec(context)
        except SATOSAAuthenticationError as error:
            error.error_id = uuid4().urn
            msg = "ERROR_ID [{err_id}]\nSTATE:\n{state}".format(err_id=error.error_id,
                                                                state=json.dumps(
                                                                    error.state.state_dict,
                                                                    indent=4))
            satosa_logging(logger, logging.ERROR, msg, error.state, exc_info=True)
            return self._handle_satosa_authentication_error(error)

    def _load_state(self, context):
        """
        Load a state to the context

        :type context: satosa.context.Context
        :param context: Session context
        """
        try:
            state = cookie_to_state(context.cookie, self.config["COOKIE_STATE_NAME"],
                                    self.config["STATE_ENCRYPTION_KEY"])
        except SATOSAStateError:
            state = State()
        context.state = state

    def _save_state(self, resp, context):
        """
        Saves a state from context to cookie

        :type resp: satosa.response.Response
        :type context: satosa.context.Context

        :param resp: The response
        :param context: Session context
        """

        cookie = state_to_cookie(context.state, self.config["COOKIE_STATE_NAME"], "/",
                                 self.config["STATE_ENCRYPTION_KEY"])
        resp.headers.append(tuple(cookie.output().split(": ", 1)))

    def run(self, context):
        """
        Runs the satosa proxy with the given context.

        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: The request context
        :return: response
        """
        try:
            self._load_state(context)
            spec = self.module_router.endpoint_routing(context)
            resp = self._run_bound_endpoint(context, spec)
            self._save_state(resp, context)
        except SATOSANoBoundEndpointError:
            raise
        except SATOSAError:
            satosa_logging(logger, logging.ERROR, "Uncaught SATOSA error", context.state,
                           exc_info=True)
            raise
        except Exception as err:
            satosa_logging(logger, logging.ERROR, "Uncaught exception", context.state,
                           exc_info=True)
            raise SATOSAUnknownError("Unknown error") from err
        return resp
