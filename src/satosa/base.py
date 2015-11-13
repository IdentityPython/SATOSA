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
from satosa.logging import satosaLogging
from satosa.plugin_loader import load_backends, load_frontends, load_micro_services
# from satosa.response import Response
from satosa.routing import ModuleRouter

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
        backends = load_backends(self.config, self._auth_resp_callback_func,
                                 self.config.INTERNAL_ATTRIBUTES)
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

    def _auth_req_callback_func(self, context, internal_request, state):
        """
        This function is called by a frontend module when an authorization request has been processed.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal_data.InternalRequest
        :type state: satosa.state.State

        :param context: The request context
        :param internal_request: request processed by the frontend
        :param state: the current state

        :return: response
        """
        satosaLogging(LOGGER, logging.INFO, "Requesting provider: {}".format(internal_request.requestor), state)
        # LOGGER.info("Requesting provider: {}".format(internal_request.requestor))
        context.request = None
        backend = self.module_router.backend_routing(context, state)
        self.consent_module.save_state(internal_request, state)
        UserIdHasher.save_state(internal_request, state)
        if self.request_micro_services:
            internal_request = self.request_micro_services.process_service_queue(context, internal_request, state)
        return backend.start_auth(context, internal_request, state)

    def _auth_resp_callback_func(self, context, internal_response, state):
        """
        This function is called by a backend module when the authorization is complete.

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :type state: satosa.state.State

        :param context: The request context
        :param internal_response: The authentication response
        :param state: The current state
        :return: response
        """

        context.request = None
        internal_response = UserIdHasher.set_id(self.config.USER_ID_HASH_SALT, internal_response,
                                                state)
        if self.response_micro_services:
            internal_response = self.response_micro_services.process_service_queue(context, internal_response, state)
        return self.consent_module.manage_consent(context, internal_response, state)

    def _consent_resp_callback_func(self, context, internal_response, state):
        """
        This function is called by the consent module when the consent step is done

        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :type state: satosa.state.State

        :param context: The response context
        :param internal_response: The authentication response
        :param state: The current state
        :return: response
        """
        context.request = None
        frontend = self.module_router.frontend_routing(context, state)
        return frontend.handle_authn_response(context, internal_response, state)

    def _handle_satosa_error(self, error):
        """
        Sends a response to the requestor about the error

        :type error: satosa.exception.SATOSAError

        :param error: The exception
        :return: response
        """
        context = Context()
        frontend = self.module_router.frontend_routing(context, error.state)
        return frontend.handle_backend_error(error)

    def _run_bound_endpoint(self, context, spec):
        """

        :type context: satosa.context.Context
        :type spec: ((satosa.context.Context, Any) -> Any, Any) | (satosa.context.Context, Any) -> Any

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
            satosaLogging(LOGGER, logging.ERROR, msg, error.state, exc_info=1)
            # LOGGER.exception("ERROR_ID [{err_id}]\nSTATE:\n{state}".format(err_id=error.error_id,
            #                                                                state=json.dumps(error.state._state_dict,
            #                                                                                 indent=4)))
            return self._handle_satosa_error(error)

    def run(self, context):
        """
        Runs the satosa proxy with the given context.

        :type context: satosa.context.Context

        :param context: The request context
        :return: response
        """
        try:
            spec = self.module_router.endpoint_routing(context)
            resp = self._run_bound_endpoint(context, spec)
        except SATOSAError:
            LOGGER.exception("uncaught SATOSA error")
            raise
        except Exception as err:
            LOGGER.exception("uncaught exception")
            raise SATOSAUnknownError("Unknown error") from err
        return resp
