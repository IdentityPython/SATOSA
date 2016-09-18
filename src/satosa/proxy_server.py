import io
import json
import logging
import logging.config
import sys
from urllib.parse import parse_qsl

import pkg_resources

from .base import SATOSABase
from .context import Context
from .response import ServiceError, NotFound
from .routing import SATOSANoBoundEndpointError

logger = logging.getLogger(__name__)


def unpack_get(environ):
    """
    Unpacks a redirect request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    if "QUERY_STRING" in environ:
        return dict(parse_qsl(environ["QUERY_STRING"]))

    return None


def unpack_post(environ, content_length):
    """
    Unpacks a post request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    post_body = environ['wsgi.input'].read(content_length).decode("utf-8")
    data = None
    if environ["CONTENT_TYPE"] == "application/x-www-form-urlencoded":
        data = dict(parse_qsl(post_body))
    elif environ["CONTENT_TYPE"] == "application/json":
        data = json.loads(post_body)

    logger.debug("unpack_post:: %s", data)
    return data


def unpack_request(environ, content_length=0):
    """
    Unpacks a get or post request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    data = None
    if environ["REQUEST_METHOD"] == "GET":
        data = unpack_get(environ)
    elif environ["REQUEST_METHOD"] == "POST":
        data = unpack_post(environ, content_length)

    logger.debug("read request data: %s", data)
    return data


class ToBytesMiddleware(object):
    """Converts a message to bytes to be sent by WSGI server."""

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

        if isinstance(data, str):
            return data.encode("utf-8")

        return data


class WsgiApplication(SATOSABase):
    def __init__(self, config):
        super().__init__(config)

    def __call__(self, environ, start_response, debug=False):
        path = environ.get('PATH_INFO', '').lstrip('/')
        if ".." in path or path == "":
            resp = NotFound("Couldn't find the page you asked for!")
            return resp(environ, start_response)

        context = Context()
        context.path = path

        # copy wsgi.input stream to allow it to be re-read later by satosa plugins
        # see: http://stackoverflow.com/questions/1783383/how-do-i-copy-wsgi-input-if-i-want-to-process-post-data-more-than-once
        content_length = int(environ.get('CONTENT_LENGTH', '0') or '0')
        body = io.BytesIO(environ['wsgi.input'].read(content_length))
        environ['wsgi.input'] = body
        context.request = unpack_request(environ, content_length)
        environ['wsgi.input'].seek(0)

        context.cookie = environ.get("HTTP_COOKIE", "")
        context.request_authorization = environ.get("HTTP_AUTHORIZATION", "")

        try:
            resp = self.run(context)
            if isinstance(resp, Exception):
                raise resp
            return resp(environ, start_response)
        except SATOSANoBoundEndpointError:
            resp = NotFound("Couldn't find the page you asked for!")
            return resp(environ, start_response)
        except Exception as err:
            logger.exception("%s" % err)
            if debug:
                raise

            resp = ServiceError("%s" % err)
            return resp(environ, start_response)


def make_app(satosa_config):
    try:
        if "LOGGING" in satosa_config:
            logging.config.dictConfig(satosa_config["LOGGING"])
        else:
            stderr_handler = logging.StreamHandler(sys.stderr)
            stderr_handler.setLevel(logging.DEBUG)

            root_logger = logging.getLogger("")
            root_logger.addHandler(stderr_handler)
            root_logger.setLevel(logging.DEBUG)

        logger.info("Running SATOSA version %s", pkg_resources.get_distribution("SATOSA").version)
        return ToBytesMiddleware(WsgiApplication(satosa_config))
    except Exception:
        logger.exception("Failed to create WSGI app.")
        raise
