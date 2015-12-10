import logging

from saml2.httputil import NotFound
from saml2.httputil import ServiceError
from saml2.httputil import Unauthorized

from satosa.base import SATOSABase
from satosa.context import Context
from satosa.routing import SATOSANoBoundEndpointError
from satosa.util import unpack_either

logger = logging.getLogger(__name__)


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
