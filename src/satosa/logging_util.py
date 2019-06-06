from uuid import uuid4
from satosa.state import State as SatosaState

# The state key for saving the session id in the state
LOGGER_STATE_KEY = "SESSION_ID"


def satosa_logging(logger: logging, loglevel: int, message: str, state: SatosaState, **kwargs) -> None:
    """
    Adds a session ID to the message.
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
    logger.log(loglevel, "[{id}] {msg}".format(id=session_id, msg=message), **kwargs)
