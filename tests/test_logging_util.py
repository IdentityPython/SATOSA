import logging
import pytest
from satosa.exception import SATOSAConfigurationError
from satosa.succinct_log_filter import SuccinctLogFilter

class Mytest1:
    def log_something(self, mylogger, msg):
        mylogger.info(msg)


def test00_invalid_conf():
    logger = logging.getLogger('test00')
    SUCCINCT_LOG_INVALID_CONF = {'satosa.state:satosa_logging': None}
    with pytest.raises(SATOSAConfigurationError):
        logger.addFilter(SuccinctLogFilter(SUCCINCT_LOG_INVALID_CONF))


def test01_do_not_filter(caplog):
    logger01 = logging.getLogger('test01')
    logger01.setLevel(logging.DEBUG)
    f = SuccinctLogFilter({})
    logger01.addFilter(f)
    logger01.debug('01testmessage')
    assert '01testmessage' in caplog.messages


def test02_skip_message(caplog):
    logger02 = logging.getLogger('test02')
    logger02.setLevel(logging.DEBUG)
    f = SuccinctLogFilter({'test_logging_util:log_something': False})
    logger02.addFilter(f)
    Mytest1().log_something(logger02, '02testmessage')
    assert '02testmessage' not in caplog.messages


def test03_trunc_message(caplog):
    logger03 = logging.getLogger('test03')
    logger03.setLevel(logging.DEBUG)
    f = SuccinctLogFilter({'test_logging_util:log_something': 5})
    logger03.addFilter(f)
    Mytest1().log_something(logger03, '03testmessage')
    assert '03tes' in caplog.messages


def test04_prefix_message(caplog):
    logger04 = logging.getLogger('test04')
    logger04.setLevel(logging.DEBUG)
    prefix = '   ======== '
    msg = '04testmessage'
    f = SuccinctLogFilter({'test_logging_util:log_something': prefix})
    logger04.addFilter(f)
    Mytest1().log_something(logger04, msg)
    assert (prefix + msg) in caplog.messages

def shorten_url(url, maxlen):
    from urllib.parse import urlparse, parse_qs
    def shorten_query_arg(arg: tuple):
        key: str = arg[0]
        values: list = arg[1]
        qa = ''
        for v in values:
            v_short = v if len(v) < 10 else '[..]'
            qa += key + '=' + v_short
        return qa

    if len(req['url']) < maxlen:
        return req['url']
    else:
        u = urlparse(url)
        params = ';' + u.params if u.params else ''
        query_args = parse_qs(u.query)
        query_shortened = '  '.join(list(map(shorten_query_arg, query_args.items())))
        return u.netloc + u.path + params + query_shortened

# def test05_change_loglevel(caplog):
#     def chg_loglevel(record: logging.LogRecord) -> logging.LogRecord:
#         record.msg = shorten_url(record.msg, 67)
#         return record
#
#     logger05 = logging.getLogger('test05')
#     logger05.setLevel(logging.WARNING)
#     msg = 'https://sp1.test.wpv.portalverbund.at/Shibboleth.sso/Login?target=https%3A%2F%2Fsp1.test.wpv.portalverbund.at%2F/secure/echo_wpv.php&entityID=https://proxy2.test.wpv.portalverbund.at/idp_proxy.xml&return=&entityID=https://proxy2.test.wpv.portalverbund.at/secure/blahblah.html'
#     f = SuccinctLogFilter({'test_logging_util:log_something': chg_loglevel})
#     logger05.addFilter(f)
#     Mytest1().log_something(logger05, msg)
#     assert '???' in caplog.messages
#

