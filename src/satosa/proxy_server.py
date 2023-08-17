import json
import logging
import logging.config
from io import BytesIO
from urllib.parse import parse_qsl as _parse_query_string

from cookies_samesite_compat import CookiesSameSiteCompatMiddleware

import satosa

from .base import SATOSABase
from .context import Context
from .response import ServiceError
from .response import NotFound


logger = logging.getLogger(__name__)


def parse_query_string(data):
    query_param_pairs = _parse_query_string(data)
    query_param_dict = dict(query_param_pairs)
    if "resource" in query_param_dict:
        query_param_dict["resource"] = [t[1] for t in query_param_pairs if t[0] == "resource"]
    return query_param_dict


def unpack_get(environ):
    """
    Unpacks a redirect request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    return parse_query_string(environ.get("QUERY_STRING"))


def unpack_post(environ, content_length):
    """
    Unpacks a post request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    post_body = environ['wsgi.input'].read(content_length).decode("utf-8")
    data = None
    if "application/x-www-form-urlencoded" in environ["CONTENT_TYPE"]:
        data = parse_query_string(post_body)
    elif "application/json" in environ["CONTENT_TYPE"]:
        data = json.loads(post_body)

    logline = "unpack_post:: {}".format(data)
    logger.debug(logline)
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

    logline = "read request data: {}".format(data)
    logger.debug(logline)
    return data


def collect_server_headers(environ):
    headers = {
        header_name: header_value
        for header_name, header_value in environ.items()
        if header_name.startswith("SERVER_")
    }
    return headers


def collect_http_headers(environ):
    headers = {
        header_name: header_value
        for header_name, header_value in environ.items()
        if (
            header_name.startswith("HTTP_")
            or header_name.startswith("REMOTE_")
        )
    }
    return headers


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
        body = BytesIO(environ['wsgi.input'].read(content_length))
        environ['wsgi.input'] = body

        context.request = unpack_request(environ, content_length)
        context.request_uri = environ.get("REQUEST_URI")
        context.request_method = environ.get("REQUEST_METHOD")
        context.qs_params = parse_query_string(environ.get("QUERY_STRING"))
        context.server = collect_server_headers(environ)
        context.http_headers = collect_http_headers(environ)
        context.cookie = context.http_headers.get("HTTP_COOKIE", "")
        context.request_authorization = context.http_headers.get("HTTP_AUTHORIZATION", "")

        environ['wsgi.input'].seek(0)

        logline = {
            "message": "Proxy server received request",
            "request_method": context.request_method,
            "request_uri": context.request_uri,
            "content_length": content_length,
            "request_data": context.request,
            "query_params": context.qs_params,
            "http_headers": context.http_headers,
            "server_headers": context.server,
        }
        logger.debug(logline)

        try:
            resp = self.run(context)
            if isinstance(resp, Exception):
                raise resp
            return resp(environ, start_response)
        except Exception as e:
            logger.exception(str(e))
            if debug:
                raise

            resp = ServiceError("%s" % e)
            return resp(environ, start_response)


def make_app(satosa_config):
    try:
        default_logging_config = {
            "version": 1,
            "formatters": {
                "simple": {
                    "format": "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s] %(message)s"
                }
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "level": "DEBUG",
                    "formatter": "simple",
                }
            },
            "loggers": {"satosa": {"level": "DEBUG"}},
            "root": {"level": "DEBUG", "handlers": ["stdout"]},
        }
        logging.config.dictConfig(satosa_config.get("LOGGING", default_logging_config))

        logger.info("Running SATOSA version {v}".format(v=satosa.__version__))

        res1 = WsgiApplication(satosa_config)
        res2 = CookiesSameSiteCompatMiddleware(res1, satosa_config)
        res3 = ToBytesMiddleware(res2)
        res = res3

        return res
    except Exception:
        logline = "Failed to create WSGI app."
        logger.exception(logline)
        raise
