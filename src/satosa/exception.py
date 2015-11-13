import json


class SATOSAError(Exception):
    pass


class SATOSAConfigurationError(SATOSAError):
    pass


class SATOSACriticalError(SATOSAError):
    pass

class SATOSAUnknownError(SATOSAError):
    pass

class SATOSAAuthenticationError(SATOSAError):
    def __init__(self, state, message, *args, **kwargs):
        super(SATOSAError, self).__init__(message, *args, **kwargs)
        self._message = "Authentication failed. Error id [{error_id}]"
        self.state = state.copy()
        self.error_id = 0

    @property
    def message(self):
        return self._message.format(error_id=self.error_id)
