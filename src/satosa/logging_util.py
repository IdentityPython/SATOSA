LOG_FMT = "[{id}] {message}"


def get_session_id(state):
    session_id = getattr(state, "session_id", None) or "UNKNOWN"
    return session_id


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
    session_id = get_session_id(state)
    logline = LOG_FMT.format(id=session_id, message=message)
    logger.log(level, logline, **kwargs)
