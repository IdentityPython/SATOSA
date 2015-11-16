"""
The SATOSA main module
"""
import json
import logging
import random
from satosa.consent import ConsentModule
from satosa.context import Context
from satosa.exception import SATOSAError, SATOSAAuthenticationError, SATOSAUnknownError
from satosa.internal_data import UserIdHasher
from satosa.logging import satosa_logging
from satosa.plugin_loader import load_backends, load_frontends, load_micro_services
from satosa.response import Response
from satosa.routing import ModuleRouter
from satosa.state import cookie_to_state, SATOSAStateError, State, state_to_cookie

__author__ = 'mathiashedstrom'

LOGGER = logging.getLogger(__name__)

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
        if config is None:
            raise ValueError("Missing configuration")

        self.config = config
        LOGGER.info("Loading backend modules...")
        backends = load_backends(self.config, self._auth_resp_callback_func, self.config.INTERNAL_ATTRIBUTES)
        LOGGER.info("Loading frontend modules...")
        frontends = load_frontends(self.config, self._auth_req_callback_func,
                                   self.config.INTERNAL_ATTRIBUTES)
        self.consent_module = ConsentModule(config, self._consent_resp_callback_func)
        # TODO register consent_module endpoints to module_router. Just add to backend list?
        if self.consent_module.enabled:
            backends["consent"] = self.consent_module

        LOGGER.info("Loading micro services...")
        self.request_micro_services = None
        self.response_micro_services = None
        if "MICRO_SERVICES" in self.config:
            self.request_micro_services, self.response_micro_services = load_micro_services(self.config.PLUGIN_PATH,
                                                                                            self.config.MICRO_SERVICES)
        self.module_router = ModuleRouter(frontends, backends)

    def _auth_req_callback_func(self, context, internal_request):
        """
        This function is called by a frontend module when an authorization request has been processed.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal_data.InternalRequest
        :rtype: satosa.response.Response

        :param context: The request context
        :param internal_request: request processed by the frontend

        :return: response
        """
        state = context.state
        satosa_logging(LOGGER, logging.INFO, "Requesting provider: {}".format(internal_request.requestor), state)
        context.request = None
        backend = self.module_router.backend_routing(context)
        self.consent_module.save_state(internal_request, state)
        UserIdHasher.save_state(internal_request, state)
        if self.request_micro_services:
            internal_request = self.request_micro_services.process_service_queue(context, internal_request)
        return backend.start_auth(context, internal_request)

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
        state = context.state
        internal_response = UserIdHasher.set_id(self.config.USER_ID_HASH_SALT, internal_response,
                                                state)
        if self.response_micro_services:
            internal_response = self.response_micro_services.process_service_queue(context, internal_response)
        return self.consent_module.manage_consent(context, internal_response)

    def _consent_resp_callback_func(self, context, internal_response):
        """
        This function is called by the consent module when the consent step is done

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse

        :param context: The response context
        :param internal_response: The authentication response
        :return: response
        """
        context.request = None
        frontend = self.module_router.frontend_routing(context)
        return frontend.handle_authn_response(context, internal_response)

    def _handle_satosa_authentication_error(self, error):
        """
        Sends a response to the requestor about the error

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
        :type spec: ((satosa.context.Context, Any) -> satosa.response.Response, Any) | (satosa.context.Context) -> satosa.response.Response

        :param context: The request context
        :param spec: bound endpoint function
        :return: response
        """
        try:
            if isinstance(spec, tuple):
                return spec[0](context, *spec[1:])
            else:
                return spec(context)
        except SATOSAAuthenticationError as error:
            error.error_id = random.getrandbits(50)
            msg = "ERROR_ID [{err_id}]\nSTATE:\n{state}".format(err_id=error.error_id,
                                                                           state=json.dumps(error.state._state_dict,
                                                                                            indent=4))
            satosa_logging(LOGGER, logging.ERROR, msg, error.state, exc_info=True)
            return self._handle_satosa_authentication_error(error)

    def _load_state(self, context):
        """
        Load a state to the context

        :type context: satosa.context.Context
        :param context: Session context
        """
        try:
            state = cookie_to_state(context.cookie, self.config.COOKIE_STATE_NAME, self.config.STATE_ENCRYPTION_KEY)
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
        if isinstance(resp, Response):
            resp.addCookie(state_to_cookie(context.state, self.config.COOKIE_STATE_NAME, "/",
                                           self.config.STATE_ENCRYPTION_KEY))
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
        except SATOSAError:
            satosa_logging(LOGGER, logging.ERROR, "Uncaught SATOSA error", context.state, exc_info=True)
            raise
        except Exception as err:
            satosa_logging(LOGGER, logging.ERROR, "Uncaught exception", context.state, exc_info=True)
            raise SATOSAUnknownError("Unknown error") from err
        return resp
