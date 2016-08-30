"""
Response objects used in satosa
"""


class Response(object):
    """
    A response object
    """
    # _template = None
    _status = "200 OK"
    _content_type = "text/html"

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

        should_add_content_type = not any(header[0].lower() == "content-type" for header in self.headers)
        if should_add_content_type:
            self.headers.append(("Content-Type", _content_type))

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
        start_response(self.status, self.headers)
        return [self.message] if not isinstance(self.message, list) else self.message


class Redirect(Response):
    """
    A Redirect response
    """
    _status = "302 Found"

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
        super().__init__(redirect_url, headers=headers, content=content)
        self.headers.append(("Location", redirect_url))


class SeeOther(Redirect):
    """
    A SeeOther response
    """
    _status = "303 See Other"

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
        super().__init__(redirect_url, headers=headers, content=content)


class NotFound(Response):
    _status = "404 Not Found"


class ServiceError(Response):
    _status = "500 Internal Service Error"


class BadRequest(Response):
    _status = "400 Bad Request"


class Created(Response):
    _status = "201 Created"


class Unauthorized(Response):
    _status = "401 Unauthorized"

    def __init__(self, message, headers=None, content=None):
        super().__init__(message, headers=headers, content=content)