#!/usr/bin/env python
import importlib
import logging
import re
import sys
import traceback

from saml2.config import config_factory
from saml2.httputil import Unauthorized
from saml2.httputil import NotFound

from saml2.httputil import ServiceError

from vopaas_proxy.back import SamlSP
from vopaas_proxy.front import SamlIDP
from vopaas_proxy.util.attribute_module import NoUserData

LOGGER = logging.getLogger("")
LOGFILE_NAME = 's2s.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)


class WsgiApplication(object):
    def __init__(self, config_file, entityid=None, debug=False):
        self.urls = []
        self.cache = {}
        self.debug = debug

        sp_conf = config_factory("sp", config_file)
        idp_conf = config_factory("idp", config_file)

        self.config = {
            "SP": sp_conf,
            "IDP": idp_conf
        }

        conf = importlib.import_module(config_file)
        self.attribute_module = conf.ATTRIBUTE_MODULE
        # If entityID is set it means this is a proxy in front of one IdP
        if entityid:
            self.entity_id = entityid
            self.sp_args = {}
        else:
            self.entity_id = None
            self.sp_args = {"discosrv": conf.DISCO_SRV}

        sp = SamlSP(None, None, self.config["SP"], self.cache, **self.sp_args)
        self.urls.extend(sp.register_endpoints())

        idp = SamlIDP(None, None, self.config["IDP"], self.cache, None)
        self.urls.extend(idp.register_endpoints())

    def incoming(self, info, environ, start_response, relay_state):
        """
        An Authentication request has been requested, this is the second step
        in the sequence

        :param info: Information about the authentication request
        :param environ: WSGI environment
        :param start_response: WSGI start_response
        :param relay_state:

        :return: response
        """

        # If I know which IdP to authenticate at return a redirect to it
        inst = SamlSP(environ, start_response, self.config["SP"],
                      self.cache, self.outgoing, **self.sp_args)
        if self.entity_id:
            state_key = inst.store_state(info["authn_req"], relay_state,
                                         info["req_args"])
            return inst.authn_request(self.entity_id, state_key)
        else:
            # start the process by finding out which IdP to authenticate at
            return inst.disco_query(info["authn_req"], relay_state,
                                    info["req_args"])

    def outgoing(self, response, instance):
        """
        An authentication response has been received and now an authentication
        response from this server should be constructed.

        :param response: The Authentication response
        :param instance: SP instance that received the authentication response
        :return: response
        """

        _idp = SamlIDP(instance.environ, instance.start_response,
                       self.config["SP"], self.cache, self.outgoing)

        _state = instance.sp.state[response.in_response_to]
        orig_authn_req, relay_state, req_args = instance.sp.state[_state]

        # The Subject NameID
        subject = response.get_subject()
        # Diverse arguments needed to construct the response
        resp_args = _idp.idp.response_args(orig_authn_req)

        # Slightly awkward, should be done better
        _authn_info = response.authn_info()[0]
        _authn = {"class_ref": _authn_info[0], "authn_auth": _authn_info[1][0]}

        # This is where any possible modification of the assertion is made
        try:
            response.ava = self.attribute_module.get_attributes(response.ava)
        except NoUserData:
            LOGGER.error(
                "User authenticated at IdP but not found by attribute module.")
            raise

        # Will signed the response by default
        resp = _idp.construct_authn_response(
            response.ava, name_id=subject, authn=_authn,
            resp_args=resp_args, relay_state=relay_state, sign_response=True)

        return resp

    def run_entity(self, spec, environ, start_response):
        """
        Picks entity and method to run by that entity.

        :param spec: a tuple (entity_type, response_type, binding)
        :param environ: WSGI environ
        :param start_response: WSGI start_response
        :return:
        """

        if isinstance(spec, tuple):
            if spec[0] == "SP":
                inst = SamlSP(environ, start_response, self.config["SP"],
                              self.cache,
                              self.outgoing, **self.sp_args)
            else:
                inst = SamlIDP(environ, start_response, self.config["IDP"],
                               self.cache,
                               self.incoming)

            func = getattr(inst, spec[1])
            return func(*spec[2:])
        else:
            return spec()

    def run_server(self, environ, start_response):
        """
        The main WSGI application.

        If nothing matches return NotFound.

        :param environ: The HTTP application environment
        :param start_response: The application to run when the handling of the
            request is done
        :return: The response as a list of lines
        """

        path = environ.get('PATH_INFO', '').lstrip('/')
        if ".." in path:
            resp = Unauthorized()
            return resp(environ, start_response)

        for regex, spec in self.urls:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['oic.url_args'] = match.groups()[0]
                except IndexError:
                    environ['oic.url_args'] = path

                try:
                    return self.run_entity(spec, environ, start_response)
                except Exception as err:
                    if not self.debug:
                        print("%s" % err, file=sys.stderr)
                        traceback.print_exc()
                        LOGGER.exception("%s" % err)
                        resp = ServiceError("%s" % err)
                        return resp(environ, start_response)
                    else:
                        raise

        LOGGER.debug("unknown side: %s" % path)
        resp = NotFound("Couldn't find the side you asked for!")
        return resp(environ, start_response)
