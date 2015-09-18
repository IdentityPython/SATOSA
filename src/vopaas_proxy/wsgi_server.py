#!/usr/bin/env python
import importlib
import logging
import sys
import traceback

from saml2.httputil import Unauthorized
from saml2.httputil import NotFound

from saml2.httputil import ServiceError
from vopaas_proxy.plugin_loader import load_backends, load_frontends
from vopaas_proxy.request_context import RequestContext
from vopaas_proxy.routing import ModuleRouter
from vopaas_proxy.service import unpack_either

LOGGER = logging.getLogger("")
LOGFILE_NAME = 's2s.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)


class WsgiApplication(object):
    def __init__(self, config_file, debug=False):
        self.debug = debug
        conf = importlib.import_module(config_file)

        backends = load_backends(conf, self.outgoing)
        frontends = load_frontends(conf, self.incoming)

        self.module_router = ModuleRouter(frontends, backends)

    def incoming(self, context, internal_request, state):
        """
        An Authentication request has been requested, this is the second step
        in the sequence

        :param info: Information about the authentication request
        :param environ: WSGI environment
        :param start_response: WSGI start_response
        :param state_key:

        :return: response
        """
        backend, state = self.module_router.incoming(context, state)
        return backend.start_auth(context, internal_request, state)

    def outgoing(self, context, internal_response, state):
        """
        An authentication response has been received and now an authentication
        response from this server should be constructed.

        :param internal_response: The Authentication response
        :param instance: SP instance that received the authentication response
        :return: response
        """
        frontend, state = self.module_router.outgoing(state)
        return frontend.handle_authn_response(context, internal_response, state)

    def run_entity(self, request_context, spec):
        """
        Picks entity and method to run by that entity.

        :param spec: a tuple (entity_type, response_type, binding)
        :param environ: WSGI environ
        :param start_response: WSGI start_response
        :return:
        """

        if isinstance(spec, tuple):
            return spec[0](request_context, *spec[1:])
        else:
            return spec()

    def run_server(self, environ, start_response):
        """
        The main WSGI application.

        If nothing matches return NotFound.

        :param environ: The HTTP application environment
        :param start_response: The application to run when the handling of the
            request is done
        :return: The response as a list of lines
        """

        path = environ.get('PATH_INFO', '').lstrip('/')
        if ".." in path:
            resp = Unauthorized()
            return resp(environ, start_response)

        context = RequestContext()
        context.path = path
        context.request = unpack_either(environ)

        spec = self.module_router.url_routing(context)
        if spec:
            try:

                resp = self.run_entity(context, spec)
                return resp(environ, start_response)
            except Exception as err:
                if not self.debug:
                    print("%s" % err, file=sys.stderr)
                    traceback.print_exc()
                    LOGGER.exception("%s" % err)
                    resp = ServiceError("%s" % err)
                    return resp(environ, start_response)
                else:
                    raise
        LOGGER.debug("unknown side: %s" % path)
        resp = NotFound("Couldn't find the side you asked for!")
        return resp(environ, start_response)
