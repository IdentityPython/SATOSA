""" granular filtering and shortening of log messages """
import collections
import logging
from satosa.exception import SATOSAConfigurationError

"""
the log filter dict uses following format:
  key: 'module:function_name'
  values:
      bool: False: skip message; True: leave message unmolested
      int:  truncate message to int characters
      str: prefix message with this string (for emphasis etc.)
      NOT working yet: callable: process message (e.g. extract salient data from message text)
"""


class SuccinctLogFilter(logging.Filter):
    def __init__(self, log_filter_config: dict):
        for k, v in log_filter_config.items():
            if not isinstance(k, str):
                raise SATOSAConfigurationError('LogFilter key must be of type str')
            if isinstance(v, bool) or \
               isinstance(v, int) or \
               isinstance(v, str) or \
               isinstance(v, collections.Callable):
                self.config = log_filter_config
            else:
                raise SATOSAConfigurationError('LogFilter value must be None or of type int, str or callable')

    def filter(self, record: logging.LogRecord) -> bool:
        _from = "{}:{}".format(record.module, record.funcName)
        if not hasattr(self, 'config'):
            return True  # handle strange 2nd call
        if _from not in self.config:
            return True
        _val = self.config[_from]
        if isinstance(_val, bool):
            return _val
        elif isinstance(_val, int):
            record.msg = record.msg[:_val]
        elif isinstance(_val, str):
            record.msg = _val + record.msg
        elif isinstance(_val, collections.Callable):
            record.msg = _val(record.msg)
        return True
