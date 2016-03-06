import io
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
                if isinstance(d, bytes):
                    encoded_data.append(d)
                else:
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

        # copy wsgi.input stream to allow it to be re-read later by satosa plugins
        # see: http://stackoverflow.com/questions/1783383/how-do-i-copy-wsgi-input-if-i-want-to-process-post-data-more-than-once
        content_length = int(environ.get('CONTENT_LENGTH', '0') or '0')
        body = io.BytesIO(environ['wsgi.input'].read(content_length))
        environ['wsgi.input'] = body
        context.request = unpack_either(environ)
        environ['wsgi.input'].seek(0)

        context.wsgi_environ = environ
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
