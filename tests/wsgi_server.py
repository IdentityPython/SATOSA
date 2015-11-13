import importlib
import logging
import sys
import traceback

from saml2.httputil import Unauthorized
from saml2.httputil import NotFound

from saml2.httputil import ServiceError
from satosa.base import SATOSABase
from satosa.context import Context
from satosa.routing import SATOSANoBoundEndpointError
from satosa.service import unpack_either

LOGGER = logging.getLogger("")
LOGFILE_NAME = 's2s.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

class WsgiApplication(object):
    def __init__(self, config, debug=False):
        self.debug = debug

        if config is None:
            raise ValueError("Missing configuration")

        self.config = config

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

        context = Context()
        context.path = path
        context.request = unpack_either(environ)
        context.cookie = environ.get("HTTP_COOKIE", "")

        try:
            # Creates a new instance of the SATOSA proxy for every call to make sure the proxy is stateless
            satosa_temporary_instance = SATOSABase(self.config)
            resp = satosa_temporary_instance.run(context)
            return resp(environ, start_response)
        except SATOSANoBoundEndpointError:
            LOGGER.debug("unknown side: %s" % path)
            resp = NotFound("Couldn't find the side you asked for!")
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
