#!/usr/bin/env python
from base64 import b64encode, b64decode
import copy
import importlib
import json
import logging
import re
import sys
import traceback

from saml2.config import IdPConfig
from saml2.httputil import Unauthorized
from saml2.httputil import NotFound

from saml2.httputil import ServiceError
from saml2.samlp import authn_request_from_string

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
        self.backends = {}
        self.backend_endpoints = {}
        self.cache = {}
        self.debug = debug

        conf = importlib.import_module(config_file)
        idp_conf = copy.deepcopy(conf.CONFIG)
        del idp_conf["backends"]
        self.config = {
            "IDP": idp_conf,
            "MODULE": conf
        }
        # TODO Remove attribute_module ?
        self.attribute_module = conf.ATTRIBUTE_MODULE
        # If entityID is set it means this is a proxy in front of one IdP
        if entityid:
            self.entity_id = entityid
            self.sp_args = {}
        else:
            self.entity_id = None
            self.sp_args = {"discosrv": conf.DISCO_SRV}

        for url, backend_info in conf.CONFIG["backends"].items():
            inst = backend_info["module"](self.outgoing, backend_info["config"])
            self.backend_endpoints[url] = inst.register_endpoints()
            self.backends[url] = inst

        idp_config = IdPConfig().load(copy.deepcopy(self.config["IDP"]),
                                      metadata_construction=False)
        idp = SamlIDP(None, None, idp_config, self.cache, None)
        self.urls.extend(idp.register_endpoints(conf))

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
        entity_id = environ["proxy.target_entity_id"]
        idp_entityid = "%s/%s" % (self.config["IDP"]["entityid"], entity_id)
        inst = self.backends[environ['proxy.backend']]
        origin_authn_req = info["authn_req"].to_string().decode("utf-8")

        request_state = {"origin_authn_req": origin_authn_req,
                         "relay_state": relay_state,
                         "proxy_idp_entityid": idp_entityid, }
        return inst.start_auth(environ, start_response, info,
                               b64encode(json.dumps(request_state).encode("UTF-8")).decode(
                                   "UTF-8"), entity_id)

    def outgoing(self, environ, start_response, response, state_key):
        """
        An authentication response has been received and now an authentication
        response from this server should be constructed.

        :param response: The Authentication response
        :param instance: SP instance that received the authentication response
        :return: response
        """

        request_state = json.loads(b64decode(state_key.encode("UTF-8")).decode("UTF-8"))
        origin_authn_req = authn_request_from_string(request_state["origin_authn_req"])

        # Change the idp entity id dynamically
        idp_config_file = copy.deepcopy(self.config["IDP"])
        idp_config_file["entityid"] = request_state["proxy_idp_entityid"]
        idp_config = IdPConfig().load(idp_config_file, metadata_construction=False)

        _idp = SamlIDP(environ, start_response,
                       idp_config, self.cache, self.outgoing)

        # Diverse arguments needed to construct the response
        resp_args = _idp.idp.response_args(origin_authn_req)

        # This is where any possible modification of the assertion is made
        try:
            response["ava"] = self.attribute_module.get_attributes(response["ava"])
        except NoUserData:
            LOGGER.error(
                "User authenticated at IdP but not found by attribute module.")
            raise

        # Will signed the response by default
        resp = _idp.construct_authn_response(
            response["ava"], name_id=response["name_id"], authn=response["auth_info"],
            resp_args=resp_args, relay_state=request_state["relay_state"], sign_response=True)

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
            if spec[0] == "IDP":
                # Add endpoints dynamically
                idp_conf_file = copy.deepcopy(self.config["IDP"])
                idp_endpoints = []
                for endp_category in self.config["MODULE"].ENDPOINTS.keys():
                    for func, endpoint in self.config["MODULE"].ENDPOINTS[endp_category].items():
                        endpoint = "{base}/{provider}/{target_id}/{endpoint}".format(
                            base=self.config["MODULE"].BASE, provider=environ["proxy.backend"],
                            target_id=environ["proxy.target_entity_id"], endpoint=endpoint)
                        idp_endpoints.append((endpoint, func))
                    idp_conf_file["service"]["idp"]["endpoints"][endp_category] = idp_endpoints
                idp_config = IdPConfig().load(idp_conf_file, metadata_construction=False)

                inst = SamlIDP(environ, start_response, idp_config,
                               self.cache,
                               self.incoming)
                func = getattr(inst, spec[1])
                return func(*spec[2:])
            return spec[0](environ, start_response, *spec[1:])
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

        path_split = path.split('/')
        backend = path_split[0]
        target_entity_id = path_split[1]
        combined_urls = self.urls + self.backend_endpoints[backend]

        for regex, spec in combined_urls:
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['oic.url_args'] = match.groups()[0]
                except IndexError:
                    environ['oic.url_args'] = path
                environ['proxy.backend'] = backend
                environ["proxy.target_entity_id"] = target_entity_id
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
