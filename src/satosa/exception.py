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
