""" granular filtering and shortening of messages to make logs succinct"""
import collections
import logging
import os
import sys

from satosa.exception import SATOSAConfigurationError
from satosa.satosa_config import SATOSAConfig
#from satosa.logging_util import get_sessionid  - >local copy


"""
the log filter dict uses following format:
  key: 'module:function_name'
  values:
      bool: False: skip message; True: leave message unmolested
      int:  truncate message to int characters
      str: prefix message with this string (for emphasis etc.)
      callable: process message (e.g. extract salient data from message text)
      tuple ('shorturl', maxlen: int): remove url parameter values for urls longer than maxlen
"""


class SATOSALogFilter(logging.Filter):
    def __init__(self, log_filter_config: dict):
        for funct, conf_opt in log_filter_config.items():
            if not isinstance(funct, str):
                raise SATOSAConfigurationError('LogFilter key must be of type str')
            if isinstance(conf_opt, bool) or \
               isinstance(conf_opt, int) or \
               isinstance(conf_opt, str) or \
               isinstance(conf_opt, collections.Callable):
                self.config = log_filter_config
            elif isinstance(conf_opt, (tuple, list)):
                if len(conf_opt) != 2 or conf_opt[0] != 'shorturl' or not isinstance(conf_opt[1], int):
                    raise SATOSAConfigurationError('LogFilter key type tuple must be ("shorturl", int)')
                self.config = log_filter_config
            else:
                raise SATOSAConfigurationError('LogFilter value must be of type int, str, callable or tuple')

    def filter(self, record: logging.LogRecord) -> bool:
        """ extra dict: if the 'state' key is found the session_id is prepended to the message """
        def _prepend_sessionid():
            if getattr(record, 'state', None):
                record.msg = "[{id}] {msg}".format(id=_get_sessionid(record.state), msg=record.msg)

        def _format_msgtext():
            if isinstance(conf_opt, int):
                record.msg = str(record.msg[:conf_opt]) + ' [..]'
            elif isinstance(conf_opt, str):
                record.msg = conf_opt + record.msg
            elif isinstance(conf_opt, collections.Callable):
                record.msg = conf_opt(record)
            elif isinstance(conf_opt, (tuple, list)) and conf_opt[0] == 'shorturl':
                record.msg = SATOSALogFilter._shorten_url(record.msg, conf_opt[1])

        def _get_conf_opt() -> object:
            _from = "{}:{}".format(record.module, record.funcName)
            return self.config.get(_from, None)

        _prepend_sessionid()
        if not hasattr(self, 'config'):
            return True  # fix: handle strange 2nd call; todo: investigate cause
        conf_opt = _get_conf_opt()
        _format_msgtext()
        if not conf_opt:
            return True
        if isinstance(conf_opt, bool):
            return conf_opt
        return True

    @classmethod
    def _shorten_url(cls, url, maxlen):
        from urllib.parse import urlparse, parse_qs
        def shorten_query_arg(arg: tuple):
            key: str = arg[0]
            values: list = arg[1]
            qa = ''
            for v in values:
                v_short = v if len(v) < 10 else '[..]'
                qa += key + '=' + v_short
            return qa

        if len(url) < maxlen:
            return url
        else:
            u = urlparse(url)
            params = ';' + u.params if u.params else ''
            query_args = parse_qs(u.query)
            query_shortened = '  '.join(list(map(shorten_query_arg, query_args.items())))

            return u.netloc + u.path + params + query_shortened

def _get_sessionid(state: dict) -> str:
    LOGGER_STATE_KEY = "SESSION_ID"
    if state is None:
        session_id = "UNKNOWN"
    else:
        try:
            session_id = state[LOGGER_STATE_KEY]
        except KeyError:
            session_id = uuid4().urn
            state[LOGGER_STATE_KEY] = session_id
    return session_id


""" 
Make the filter object as a single instance to the various loggers.
This is using the feature that a module is imported only once. 
"""
config_file = os.environ.get("SATOSA_CONFIG", "proxy_conf.yaml")
satosa_config = SATOSAConfig(config_file)

# this is a pointer to the module object instance itself:
this = sys.modules[__name__]
if 'SUCCINCT_LOG_SATOSA' in satosa_config:
    this.satosa_log_filter = SATOSALogFilter(satosa_config['SUCCINCT_LOG_SATOSA'])
else:
    this.satosa_log_filter = None

def add_satosa_log_filter(loggr: logging.Logger) -> None:
    if this.satosa_log_filter:
        loggr.addFilter(this.satosa_log_filter)
