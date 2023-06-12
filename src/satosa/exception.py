"""
Exceptions for SATOSA
"""


class SATOSAError(Exception):
    """
    Base SATOSA exception
    """
    pass


class SATOSAConfigurationError(SATOSAError):
    """
    SATOSA configuration error
    """
    pass


class SATOSAStateError(SATOSAError):
    """
    SATOSA state error.
    """
    pass


class SATOSACriticalError(SATOSAError):
    """
    SATOSA critical error
    """
    pass


class SATOSAUnknownError(SATOSAError):
    """
    SATOSA unknown error
    """
    pass


class SATOSAAuthenticationError(SATOSAError):
    """
    SATOSA authentication error.
    """

    def __init__(self, state, message, *args, **kwargs):
        """
        :type state: satosa.state.State
        :param message: str
        :param args: any
        :param kwargs: any

        :param state: Satosa state
        :param message: A test message
        :param args: whatever
        :param kwargs: whatever
        """
        super().__init__(message, *args, **kwargs)
        self._message = "Authentication failed. Error id [{error_id}]"
        self.state = state.copy()
        self.error_id = 0

    @property
    def message(self):
        """
        :rtype: str
        :return: Exception message
        """
        return self._message.format(error_id=self.error_id)


class SATOSABasicError(SATOSAError):
    """
    eduTEAMS error
    """
    def __init__(self, error):
        self.error = error


class SATOSAMissingStateError(SATOSABasicError):
    """
    SATOSA Missing State error.

    This exception should be raised when SATOSA receives a request as part of
    an authentication flow and while the session state cookie is expected for
    that step, it is not included in the request
    """
    pass


class SATOSAAuthenticationFlowError(SATOSABasicError):
    """
    SATOSA Flow error.

    This exception should be raised when SATOSA receives a request that cannot
    be serviced because previous steps in the authentication flow for that session
    cannot be found
    """
    pass


class SATOSABadRequestError(SATOSABasicError):
    """
    SATOSA Bad Request error.

    This exception should be raised when we want to return an HTTP 400 Bad Request
    """
    pass


class SATOSABadContextError(SATOSAError):
    """
    Raise this exception if validating the Context and failing.
    """
    pass


class SATOSANoBoundEndpointError(SATOSAError):
    """
    Raised when a given url path is not bound to any endpoint function
    """
    pass
