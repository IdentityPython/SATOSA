#!/usr/bin/env python
import logging
from urllib.parse import parse_qs

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_POST
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.httputil import get_post
from saml2.httputil import SeeOther
from saml2.httputil import ServiceError
from saml2.httputil import Response
from saml2.httputil import BadRequest

logger = logging.getLogger(__name__)

BINDING_MAP = {
    BINDING_HTTP_POST: "post",
    BINDING_HTTP_REDIRECT: "redirect",
    # BINDING_HTTP_ARTIFACT: "artifact",
    BINDING_SOAP: "soap",
    BINDING_DISCO: "disco"
}

INV_BINDING_MAP = {v: k for k, v in BINDING_MAP.items()}


class Service(object):
    # Common operations that all services need
    def __init__(self, environ, start_response):
        self.environ = environ
        logger.debug("ENVIRON: %s" % environ)
        self.start_response = start_response

    def unpack(self, binding):
        if binding == "redirect":
            return self.unpack_redirect()
        elif binding == "post":
            return self.unpack_post()
        elif binding == "soap":
            return self.unpack_soap()
        else:
            return self.unpack_either()

    def unpack_redirect(self):
        if "QUERY_STRING" in self.environ:
            _qs = self.environ["QUERY_STRING"]
            return dict([(k, v[0]) for k, v in parse_qs(_qs).items()])
        else:
            return None

    def unpack_post(self):
        post_body = get_post(self.environ).decode("utf-8")
        _dict = parse_qs(post_body)
        logger.debug("unpack_post:: %s" % _dict)
        try:
            return dict([(k, v[0]) for k, v in _dict.items()])
        except IOError:
            return None

    def unpack_soap(self):
        try:
            query = get_post(self.environ)
            return {"SAMLResponse": query, "RelayState": ""}
        except IOError:
            return None

    def unpack_either(self):
        if self.environ["REQUEST_METHOD"] == "GET":
            _dict = self.unpack_redirect()
        elif self.environ["REQUEST_METHOD"] == "POST":
            _dict = self.unpack_post()
        else:
            _dict = None
        logger.debug("_dict: %s" % _dict)
        return _dict

    def _operation(self, func, _dict, binding):
        logger.debug("_operation: %s" % _dict)
        if not _dict:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)
        else:
            try:
                _relay_state = _dict["RelayState"]
            except KeyError:
                _relay_state = ""
            if "SAMLResponse" in _dict:
                return func(_dict["SAMLResponse"], binding, _relay_state,
                            mtype="response")
            elif "SAMLRequest" in _dict:
                return func(_dict["SAMLRequest"], binding, _relay_state,
                            mtype="request")

    def response(self, binding, http_args, do_not_start_response=False):
        if binding == BINDING_HTTP_REDIRECT:
            for param, value in http_args["headers"]:
                if param == "Location":
                    resp = SeeOther(str(value))
                    break
            else:
                resp = ServiceError("Parameter error")
        else:
            resp = Response(http_args["data"], headers=http_args["headers"])

        if do_not_start_response:
            return resp
        else:
            return resp(self.environ, self.start_response)

    def redirect(self, func):
        """ Expects a HTTP-redirect response """

        _dict = self.unpack_redirect()
        return self._operation(func, _dict, BINDING_HTTP_REDIRECT)

    def post(self, func):
        """ Expects a HTTP-POST response """

        _dict = self.unpack_post()
        return self._operation(func, _dict, BINDING_HTTP_POST)

    def soap(self, func):
        """
        Single log out using HTTP_SOAP binding
        """
        logger.debug("- SOAP -")
        _dict = self.unpack_soap()
        logger.debug("_dict: %s" % _dict)
        return self._operation(func, _dict, BINDING_SOAP)

    def uri(self, func):
        _dict = self.unpack_either()
        return self._operation(func, _dict, BINDING_SOAP)
