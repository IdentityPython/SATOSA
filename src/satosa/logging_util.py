"""
Python logging package
"""
from uuid import uuid4

# The state key for saving the session id in the state
LOGGER_STATE_KEY = "SESSION_ID"


def satosa_logging(logger, level, message, state, **kwargs):
    """
    Adds a session ID to the message.

    :type logger: logging
    :type level: int
    :type message: str
    :type state: satosa.state.State

    :param logger: Logger to use
    :param level: Logger level (ex: logging.DEBUG/logging.WARN/...)
    :param message: Message
    :param state: The current state
    :param kwargs: set exc_info=True to get an exception stack trace in the log
    """
    if state is None:
        session_id = "UNKNOWN"
    else:
        try:
            session_id = state[LOGGER_STATE_KEY]
        except KeyError:
            session_id = uuid4().urn
            state[LOGGER_STATE_KEY] = session_id
    logger.log(level, "[{id}] {msg}".format(id=session_id, msg=message), **kwargs)
