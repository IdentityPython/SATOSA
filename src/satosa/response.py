"""
Response objects used in satosa
"""
from urllib.parse import quote

import six

__author__ = 'mathiashedstrom'


class Response(object):
    """
    A response object
    """
    # _template = None
    _status = '200 OK'
    _content_type = 'text/html'

    def __init__(self, message=None, status=None, headers=None, content=None):
        """
        Creates a Responses
        :type message: str
        :type status: str
        :type headers: list[(str, str)]
        :type content: str

        :param message: The response message
        :param status: The response status code
        :param headers: A list of headers
        :param content: The content type
        """
        _content_type = content if content is not None else self._content_type
        self.status = status if status is not None else self._status
        self.headers = headers if headers is not None else []
        self.message = message

        addcontenttype = True
        for header in self.headers:
            if 'content-type' == header[0].lower():
                addcontenttype = False
        if addcontenttype:
            self.headers.append(('Content-type', _content_type))

    def add_cookie(self, cookie):
        """
        Adds a cookie to the response header
        :type cookie: http.cookies.SimpleCookie
        :param cookie: The cookie to be added
        """
        self.headers.append(tuple(cookie.output().split(": ", 1)))

    def __call__(self, environ, start_response):
        """
        Help method when using a WSGI application server.
        Creates a response from environ and start_response

        :type environ: dict[str, str]
        :type start_response: (str, list[(str, str)]) -> None

        :param environ: The WSGI environ
        :param start_response: The WSGI start_response
        :return:
        """
        try:
            start_response(self.status, self.headers)
        except TypeError:
            pass
        return self.to_list(self.message or geturl(environ))

    def to_list(self, message=""):
        """
        Convert message to list
        :type message: str | list[str]
        :rtype: list[str]
        :param message: message for response
        :return: A response message
        """
        if isinstance(message, six.string_types):
            return [message]
        else:
            return message


class Redirect(Response):
    """
    A Redirect response
    """
    _status = '302 Found'

    def __init__(self, redirect_url, headers=None, content=None):
        """
        Crete a redirect response

        :type redirect_url: str
        :type headers: list[(str,str)]
        :type content: str

        :param redirect_url: The redirect url
        :param headers: A list of headers
        :param content: Content type
        """
        super(Redirect, self).__init__(message=redirect_url, headers=headers, content=content)

    def __call__(self, environ, start_response):
        """
        :type environ: dict[str, str]
        :type start_response: (str, list[(str, str)]) -> None

        :param environ: The WSGI environ
        :param start_response: The WSGI start_response
        """
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.to_list()


class SeeOther(Response):
    """
    A SeeOther response
    """
    _status = '303 See Other'

    def __init__(self, redirect_url, headers=None, content=None):
        """
        Creates a SeeOther response

        :type redirect_url: str
        :type headers: list[(str, str)]
        :type content: str

        :param redirect_url: The redirect url
        :param headers: A list of headers
        :param content: The content type
        """
        super(SeeOther, self).__init__(message=redirect_url, headers=headers, content=content)

    def __call__(self, environ, start_response):
        """
        See super class method satosa.response.Redirect#__call__
        :type environ: dict[str, str]
        :type start_response: (str, list[(str, str)]) -> None

        :param environ: The WSGI environ
        :param start_response: The WSGI start_response
        """
        if self.message:
            location = self.message
            self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.to_list()


def geturl(environ, query=True, path=True, use_server_name=False):
    """Rebuilds a request URL (from PEP 333).
    You may want to chose to use the environment variables
    server_name and server_port instead of http_host in some case.
    The parameter use_server_name allows you to chose.

    :type environ: any
    :type query: str
    :type path: str
    :type use_server_name: bool
    :rtype: str

    :param environ: whiskey app environment
    :param query: Is QUERY_STRING included in URI (default: True)
    :param path: Is path included in URI (default: True)
    :param use_server_name: If SERVER_NAME/_HOST should be used instead of
        HTTP_HOST
    """
    url = [environ['wsgi.url_scheme'] + '://']
    if use_server_name:
        url.append(environ['SERVER_NAME'])
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                url.append(':' + environ['SERVER_PORT'])
        else:
            if environ['SERVER_PORT'] != '80':
                url.append(':' + environ['SERVER_PORT'])
    else:
        url.append(environ['HTTP_HOST'])
    if path:
        url.append(getpath(environ))
    if query and environ.get('QUERY_STRING'):
        url.append('?' + environ['QUERY_STRING'])
    return ''.join(url)


def getpath(environ):
    """
    Builds a path
    :type environ: dict[str, str]
    :rtype: str

    :param environ: The WSGI application environ
    :return: the path
    """
    return ''.join([quote(environ.get('SCRIPT_NAME', '')),
                    quote(environ.get('PATH_INFO', ''))])
