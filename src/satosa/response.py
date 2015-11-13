import six
from urllib.parse import quote

__author__ = 'mathiashedstrom'


class Response(object):
    _template = None
    _status = '200 OK'
    _content_type = 'text/html'
    _mako_template = None
    _mako_lookup = None

    def __init__(self, message=None, **kwargs):
        self.status = kwargs.get('status', self._status)
        self.response = kwargs.get('response', self._response)
        self.template = kwargs.get('template', self._template)
        self.mako_template = kwargs.get('mako_template', self._mako_template)
        self.mako_lookup = kwargs.get('template_lookup', self._mako_lookup)

        self.message = message

        self.headers = kwargs.get('headers', [])

        _content_type = kwargs.get('content', self._content_type)
        addContentType = True
        for header in self.headers:
            if 'content-type' == header[0].lower():
                addContentType = False
        if addContentType:
            self.headers.append(('Content-type', _content_type))

    def addCookie(self, cookie):
        self.headers.append(tuple(cookie.output().split(": ", 1)))

    def __call__(self, environ, start_response, **kwargs):
        try:
            start_response(self.status, self.headers)
        except TypeError:
            pass
        return self.response(self.message or geturl(environ), **kwargs)

    def _response(self, message="", **argv):
        if self.template:
            return [self.template % message]
        elif self.mako_lookup and self.mako_template:
            argv["message"] = message
            mte = self.mako_lookup.get_template(self.mako_template)
            return [mte.render(**argv)]
        else:
            if isinstance(message, six.string_types):
                return [message]
            else:
                return message


class Redirect(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
                '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
                '</body>\n</html>'
    _status = '302 Found'

    def __init__(self, redirect_url, **kwargs):
        super(Redirect, self).__init__(message=redirect_url, **kwargs)

    def __call__(self, environ, start_response, **kwargs):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))

class SeeOther(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
        '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
        '</body>\n</html>'
    _status = '303 See Other'

    def __init__(self, redirect_url, **kwargs):
        super(SeeOther, self).__init__(message=redirect_url, **kwargs)

    def __call__(self, environ, start_response, **kwargs):
        location = ""
        if self.message:
            location = self.message
            self.headers.append(('location', location))
        else:
            for param, item in self.headers:
                if param == "location":
                    location = item
                    break
        start_response(self.status, self.headers)
        return self.response((location, location, location))


def geturl(environ, query=True, path=True, use_server_name=False):
    """Rebuilds a request URL (from PEP 333).
    You may want to chose to use the environment variables
    server_name and server_port instead of http_host in some case.
    The parameter use_server_name allows you to chose.

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
    """Builds a path."""
    return ''.join([quote(environ.get('SCRIPT_NAME', '')),
                    quote(environ.get('PATH_INFO', ''))])
