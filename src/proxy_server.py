import argparse
import functools
import logging
import os
import ssl
import sys
from wsgiref.simple_server import make_server

from saml2.httputil import NotFound
from saml2.httputil import ServiceError
from saml2.httputil import Unauthorized
from werkzeug.debug import DebuggedApplication

from satosa.base import SATOSABase
from satosa.context import Context
from satosa.routing import SATOSANoBoundEndpointError
from satosa.satosa_config import SATOSAConfig
from satosa.util import unpack_either

logger = logging.getLogger(__name__)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)

for logger_name in ["", "satosa", "saml2"]:
    logger = logging.getLogger(logger_name)
    logger.addHandler(stdout_handler)
    logger.setLevel(logging.DEBUG)


class ToBytesMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        data = self.app(environ, start_response)

        if isinstance(data, list):
            encoded_data = []
            for d in data:
                if not isinstance(data, bytes):
                    encoded_data.append(d.encode("utf-8"))
            return encoded_data
        if not isinstance(data, bytes):
            return data.encode("utf-8")

        return data


class WsgiApplication(SATOSABase):
    def __init__(self, config):
        super(WsgiApplication, self).__init__(config)

    def run_server(self, environ, start_response, debug=False):
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
            if isinstance(resp, Exception):
                raise resp
            return resp(environ, start_response)
        except SATOSANoBoundEndpointError:
            resp = NotFound("Couldn't find the side you asked for!")
            return resp(environ, start_response)
        except Exception as err:
            logger.exception("%s" % err)
            if debug:
                raise

            resp = ServiceError("%s" % err)
            return resp(environ, start_response)


config_file = os.environ.get("SAAS_CONFIG", "proxy_conf.yaml")
server_config = SATOSAConfig(config_file)
app = ToBytesMiddleware(WsgiApplication(server_config).run_server)


def main():
    global app

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('port', type=int)
    parser.add_argument('--keyfile', type=str)
    parser.add_argument('--certfile', type=str)
    parser.add_argument('-d', action='store_true', dest="debug",
                        help="enable debug mode.")
    args = parser.parse_args()

    if (args.keyfile and not args.certfile) or (args.certfile and not args.keyfile):
        print("Both keyfile and certfile must be specified for HTTPS.")
        sys.exit()

    if args.debug:
        app.app = functools.partial(app.app, debug=True)
        app = DebuggedApplication(app)

    httpd = make_server('', args.port, app)

    if args.keyfile and args.certfile:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.check_hostname = False
        ctx.load_cert_chain(certfile=args.certfile, keyfile=args.keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


if __name__ == '__main__':
    main()
