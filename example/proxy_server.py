import argparse
import os
import sys

import cherrypy
from beaker.middleware import SessionMiddleware
from werkzeug.debug import DebuggedApplication
from satosa.satosa_config import SATOSAConfig

from satosa.wsgi_server import WsgiApplication


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
        'server.socket_host': '0.0.0.0',
        'server.socket_port': server_config.PORT
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
