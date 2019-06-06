import logging
from uuid import uuid4
import satosa.state

# The state key for saving the session id in the state
LOGGER_STATE_KEY = "SESSION_ID"


def satosa_logging(logger: logging.Logger, loglevel: int, message: str, state: satosa.state.State, **kwargs) -> None:
    """
    Adds a session ID to the message.
    :param kwargs: set exc_info=True to get an exception stack trace in the log
    """
    logger.log(loglevel, "[{id}] {msg}".format(id=get_sessionid(state), msg=message), **kwargs)


def get_sessionid(state: dict) -> str:
    if state is None:
        session_id = "UNKNOWN"
    else:
        try:
            session_id = state[LOGGER_STATE_KEY]
        except KeyError:
            session_id = uuid4().urn
            state[LOGGER_STATE_KEY] = session_id
    return session_id
