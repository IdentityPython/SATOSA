import random

__author__ = 'mathiashedstrom'

LOGGER_STATE_KEY = "SESSION_ID"
def satosaLogging(logger, level, message, state, **kwargs):
    if state is None:
        session_id = "UNKNOWN"
    else:
        try:
            session_id = state.get(LOGGER_STATE_KEY)
        except KeyError:
            session_id = random.getrandbits(50)
            state.add(LOGGER_STATE_KEY, session_id)
    logger.log(level, "[{id}] {msg}".format(id=session_id, msg=message), **kwargs)