import argparse
import os
import logging
import sys
import traceback

import cherrypy
from beaker.middleware import SessionMiddleware
from werkzeug.debug import DebuggedApplication
from saml2.httputil import Unauthorized
from saml2.httputil import NotFound

from saml2.httputil import ServiceError

from satosa.satosa_config import SATOSAConfig
from satosa.base import SATOSABase
from satosa.context import Context
from satosa.routing import NoBoundEndpointError
from satosa.service import unpack_either

LOGGER = logging.getLogger("")
LOGFILE_NAME = 's2s.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)


class WsgiApplication(SATOSABase):
    def __init__(self, config, debug=False):
        super(WsgiApplication, self).__init__(config)
        self.debug = debug

    def run_server(self, environ, start_response):
        path = environ.get('PATH_INFO', '').lstrip('/')
        if ".." in path:
            resp = Unauthorized()
            return resp(environ, start_response)

        context = Context()
        context.path = path
        context.request = unpack_either(environ)
        context.cookie = environ.get("HTTP_COOKIE", "")

        try:
            resp = self.run(context)
            return resp(environ, start_response)
        except NoBoundEndpointError:
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', action='store_true', dest="debug",
                        help="Enable debug mode.")
    parser.add_argument('-e', dest="entityid",
                        help="Entity id for the underlying IdP. If not "
                             "specified, a discovery server will be used "
                             "instead.")
    parser.add_argument(dest="proxy_config",
                        help="Configuration file for the SATOSA proxy.")
    args = parser.parse_args()

    sys.path.insert(0, os.getcwd())

    server_config = SATOSAConfig(args.proxy_config)
    wsgi_app = WsgiApplication(server_config, args.debug).run_server
    if args.debug:
        wsgi_app = DebuggedApplication(wsgi_app)

    cherrypy.config.update({
        'server.socket_host': server_config.HOST,
        'server.socket_port': server_config.PORT,
        'engine.autoreload.on': False
    })
    if server_config.HTTPS:
        cherrypy.config.update({
            'server.ssl_certificate': server_config.SERVER_CERT,
            'server.ssl_private_key': server_config.SERVER_KEY,
            'server.ssl_certificate_chain': server_config.CERT_CHAIN,
        })

    cherrypy.tree.mount(None, '/static', {
        '/': {
            'tools.staticdir.dir': server_config.STATIC_DIR,
            'tools.staticdir.on': True,
        }
    })
    cherrypy.tree.mount(None, '/robots.txt', {
        '/': {
            'tools.staticfile.on': True,
            'tools.staticfile.filename': os.path.join(server_config.STATIC_DIR,
                                                      "robots.txt")

        }
    })

    cherrypy.tree.graft(SessionMiddleware(wsgi_app, server_config.SESSION_OPTS),
                        '/')

    cherrypy.engine.start()
    cherrypy.engine.block()


if __name__ == '__main__':
    main()
