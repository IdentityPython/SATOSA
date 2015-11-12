class SATOSAError(Exception):
    pass


class SATOSAConfigurationError(SATOSAError):
    pass


class SATOSACriticalError(SATOSAError):
    pass


class SATOSAAuthenticationError(SATOSAError):
    def __init__(self, message, state, *args, **kwargs):
        super(SATOSAError, self).__init__(message, *args, **kwargs)
        self.message = message
        self.state = state.copy()
