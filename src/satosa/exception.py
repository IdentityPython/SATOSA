__author__ = 'mathiashedstrom'


class SATOSAConfigurationError(Exception):
    def __init__(self, message, *args, **kwargs):
        super(SATOSAConfigurationError, self).__init__(message, *args, **kwargs)
        self.message = message


class SATOSAError(Exception):
    def __init__(self, state, message, *args, **kwargs):
        super(SATOSAError, self).__init__(message, *args, **kwargs)
        self.message = message
        self.state = state.copy()


class AuthenticationError(SATOSAError):
    pass


class SATOSACriticalError(Exception):
    pass
