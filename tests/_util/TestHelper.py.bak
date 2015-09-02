import copy
from importlib import import_module
import urllib
from urlparse import parse_qs
import re
__author__ = 'haho0032'


def create_cookie_header(cookie_list, cookie_header=[]):
    cookies = ""
    for value in cookie_header:
        if value[0] == "Cookie":
            cookies = value[1]
    for k, v in cookie_list:
        if len(cookies) > 0:
            cookies += "; "
        cookies += v.split(";")[0]
    return [("Cookie", cookies)]

def get_url(headers):
    url = ""
    for header in headers:
        if header[0] == "location":
            url = header[1]
            break
    return url


def get_dict(url):
    req = parse_qs(url.split("?")[1])
    return req


def get_url_dict(headers):
    url = get_url(headers)
    req = parse_qs(url.split("?")[1])
    return req


def get_post_action_body(form):
        resp = re.split( r'([^=, ]+)="([^" ]+|[^," ]+)" ?',  form)
        count = 0
        action = None
        saml_response = None
        relay_state = None
        for value in resp:
            if value == "action":
                action = resp[count+1]
            if value == 'SAMLResponse':
                saml_response = resp[count+3]
            if value == "RelayState":
                relay_state = resp[count+3]
            count+=1
        body = {"SAMLResponse": saml_response, "RelayState": relay_state}
        return action, body


def get_config(config_file):
    if config_file.endswith(".py"):
            config_file = config_file[:-3]
    conf = None
    try:
        import_module('..' + config_file, 'test')
        conf = __import__(config_file)
    except:
        pass
    return conf.CONFIG