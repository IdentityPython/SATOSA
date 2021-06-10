"""
The SATOSA main module
"""
import json
import logging
import uuid

from saml2.s_utils import UnknownSystemEntity

from satosa import util
from .context import Context
from .exception import SATOSAConfigurationError
from .exception import SATOSAError, SATOSAAuthenticationError, SATOSAUnknownError
from .plugin_loader import load_backends, load_frontends
from .plugin_loader import load_request_microservices, load_response_microservices
from .routing import ModuleRouter, SATOSANoBoundEndpointError
from .state import cookie_to_state, SATOSAStateError, State, state_to_cookie

import satosa.logging_util as lu


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
            self.request_micro_services.extend(load_request_microservices(
                self.config.get("CUSTOM_PLUGIN_MODULE_PATHS"),
                self.config["MICRO_SERVICES"],
                self.config["INTERNAL_ATTRIBUTES"],
                self.config["BASE"]))
            self._link_micro_services(self.request_micro_services, self._auth_req_finish)

            self.response_micro_services.extend(
                load_response_microservices(self.config.get("CUSTOM_PLUGIN_MODULE_PATHS"),
                                            self.config["MICRO_SERVICES"],
                                            self.config["INTERNAL_ATTRIBUTES"],
                                            self.config["BASE"]))
            self._link_micro_services(self.response_micro_services, self._auth_resp_finish)

        self.module_router = ModuleRouter(frontends, backends,
                                          self.request_micro_services + self.response_micro_services)

    def _link_micro_services(self, micro_services, finisher):
        if not micro_services:
            return

        for i in range(len(micro_services) - 1):
            micro_services[i].next = micro_services[i + 1].process

        micro_services[-1].next = finisher

    def _auth_req_callback_func(self, context, internal_request):
        """
        This function is called by a frontend module when an authorization request has been
        processed.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype: satosa.response.Response

        :param context: The request context
        :param internal_request: request processed by the frontend

        :return: response
        """
        state = context.state
        state[STATE_KEY] = {"requester": internal_request.requester}

        msg = "Requesting provider: {}".format(internal_request.requester)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(state), message=msg)
        logger.info(logline)

        if self.request_micro_services:
            return self.request_micro_services[0].process(context, internal_request)

        return self._auth_req_finish(context, internal_request)

    def _auth_req_finish(self, context, internal_request):
        backend = self.module_router.backend_routing(context)
        context.request = None
        return backend.start_auth(context, internal_request)

    def _auth_resp_finish(self, context, internal_response):
        user_id_to_attr = self.config["INTERNAL_ATTRIBUTES"].get("user_id_to_attr", None)
        if user_id_to_attr:
            internal_response.attributes[user_id_to_attr] = [internal_response.subject_id]

        # remove all session state unless CONTEXT_STATE_DELETE is False
        context.state.delete = self.config.get("CONTEXT_STATE_DELETE", True)
        context.request = None

        frontend = self.module_router.frontend_routing(context)
        return frontend.handle_authn_response(context, internal_response)

    def _auth_resp_callback_func(self, context, internal_response):
        """
        This function is called by a backend module when the authorization is
        complete.

        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
        :rtype: satosa.response.Response

        :param context: The request context
        :param internal_response: The authentication response
        :return: response
        """

        context.request = None
        internal_response.requester = context.state[STATE_KEY]["requester"]

        # If configured construct the user id from attribute values.
        if "user_id_from_attrs" in self.config["INTERNAL_ATTRIBUTES"]:
            subject_id = [
                "".join(internal_response.attributes[attr]) for attr in
                self.config["INTERNAL_ATTRIBUTES"]["user_id_from_attrs"]
            ]
            internal_response.subject_id = "".join(subject_id)

        if self.response_micro_services:
            return self.response_micro_services[0].process(
                context, internal_response)

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
            error.error_id = uuid.uuid4().urn
            state = json.dumps(error.state.state_dict, indent=4)
            msg = "ERROR_ID [{err_id}]\nSTATE:\n{state}".format(
                err_id=error.error_id, state=state
            )
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline, error.state, exc_info=True)
            return self._handle_satosa_authentication_error(error)

    def _load_state(self, context):
        """
        Load state from cookie to the context

        :type context: satosa.context.Context
        :param context: Session context
        """
        try:
            state = cookie_to_state(
                context.cookie,
                self.config["COOKIE_STATE_NAME"],
                self.config["STATE_ENCRYPTION_KEY"],
            )
        except SATOSAStateError as e:
            state = State()
        finally:
            context.state = state
            msg = "Loaded state {state} from cookie {cookie}".format(state=state, cookie=context.cookie)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.info(logline)

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
            msg = "Uncaught SATOSA error"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline, exc_info=True)
            raise
        except UnknownSystemEntity as err:
            msg = "configuration error: unknown system entity " + str(err)
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline, exc_info=False)
            raise
        except Exception as err:
            msg = "Uncaught exception"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline, exc_info=True)
            raise SATOSAUnknownError("Unknown error") from err
        return resp


class SAMLBaseModule(object):
    KEY_ENTITYID_ENDPOINT = 'entityid_endpoint'
    KEY_ENABLE_METADATA_RELOAD = 'enable_metadata_reload'
    KEY_ATTRIBUTE_PROFILE = 'attribute_profile'
    KEY_ACR_MAPPING = 'acr_mapping'
    VALUE_ATTRIBUTE_PROFILE_DEFAULT = 'saml'

    def init_config(self, config):
        self.attribute_profile = config.get(
            self.KEY_ATTRIBUTE_PROFILE,
            self.VALUE_ATTRIBUTE_PROFILE_DEFAULT)
        self.acr_mapping = config.get(self.KEY_ACR_MAPPING)
        return config

    def expose_entityid_endpoint(self):
        value = self.config.get(self.KEY_ENTITYID_ENDPOINT, False)
        return bool(value)

    def enable_metadata_reload(self):
        """
        Check whether metadata reload has been enabled in config

        return: bool
        """
        value = self.config.get(self.KEY_ENABLE_METADATA_RELOAD, False)
        return bool(value)


class SAMLEIDASBaseModule(SAMLBaseModule):
    VALUE_ATTRIBUTE_PROFILE_DEFAULT = 'eidas'

    def init_config(self, config):
        config = super().init_config(config)

        spec_eidas = {
            'entityid_endpoint': True,
        }

        return util.check_set_dict_defaults(config, spec_eidas)
