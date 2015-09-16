#!/usr/bin/env python
import importlib
import logging
import sys
import traceback
from pluginbase import PluginBase

from saml2.httputil import Unauthorized
from saml2.httputil import NotFound

from saml2.httputil import ServiceError
from vopaas_proxy.routing import ModuleRouter

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
        backends = self._load_backends(conf)
        frontends = self._load_frontends(conf, list(backends.keys()))
        self.module_router = ModuleRouter(frontends, backends)

    def _load_frontends(self, config, providers):
        plugin_base = PluginBase(package='proxy_plugins')
        plugin_source = plugin_base.make_plugin_source(searchpath=config.PLUGIN_PATH)
        frontends = {}
        for frontend in config.FRONTEND_MODULES:
            frontend_plugin = plugin_source.load_plugin(frontend).setup(config.BASE)
            module_inst = frontend_plugin.module(self.incoming, frontend_plugin.config)
            frontends[frontend_plugin.receiver] = {"instance": module_inst,
                                                   "endpoints": module_inst.register_endpoints(
                                                       providers)}
        return frontends

    def _load_backends(self, config):
        plugin_base = PluginBase(package='proxy_plugins')
        plugin_source = plugin_base.make_plugin_source(searchpath=config.PLUGIN_PATH)
        backends = {}
        for backend in config.BACKEND_MODULES:
            backend_plugin = plugin_source.load_plugin(backend).setup(config.BASE)
            module_inst = backend_plugin.module(self.outgoing, backend_plugin.config)
            backends[backend_plugin.provider] = {"instance": module_inst,
                                                 "endpoints": module_inst.register_endpoints()}
        return backends

    def incoming(self, environ, start_response, info, state):
        """
        An Authentication request has been requested, this is the second step
        in the sequence

        :param info: Information about the authentication request
        :param environ: WSGI environment
        :param start_response: WSGI start_response
        :param state_key:

        :return: response
        """
        backend, state = self.module_router.incoming(environ, state)
        return backend.start_auth(environ, start_response, info, state)

    def outgoing(self, environ, start_response, internal_response, state):
        """
        An authentication response has been received and now an authentication
        response from this server should be constructed.

        :param internal_response: The Authentication response
        :param instance: SP instance that received the authentication response
        :return: response
        """
        frontend, state = self.module_router.outgoing(state)
        return frontend.handle_authn_response(environ, start_response, internal_response, state)

    def run_entity(self, environ, start_response, spec):
        """
        Picks entity and method to run by that entity.

        :param spec: a tuple (entity_type, response_type, binding)
        :param environ: WSGI environ
        :param start_response: WSGI start_response
        :return:
        """

        if isinstance(spec, tuple):
            return spec[0](environ, start_response, *spec[1:])
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

        spec = self.module_router.url_routing(environ, path)
        if spec:
            try:
                return self.run_entity(environ, start_response, spec)
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
