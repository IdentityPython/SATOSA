__author__ = 'mathiashedstrom'


class SATOSAError(Exception):
    def __init__(self, state, message, *args, **kwargs):
        super(SATOSAError, self).__init__(message, *args, **kwargs)
        self.message = message
        self.state = state.copy()


class AuthenticationError(SATOSAError):
    pass


class SATOSACriticalError(Exception):
    pass
