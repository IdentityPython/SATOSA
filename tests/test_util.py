# pylint: disable = missing-docstring
import base64
import random
import tempfile
import sys

from saml2 import server, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.authn_context import AuthnBroker, authn_context_class_ref, PASSWORD
from saml2.cert import OpenSSLWrapper
from saml2.client import Saml2Client
from saml2.config import config_factory, Config
from saml2.metadata import entity_descriptor, entities_descriptor
from saml2.saml import name_id_from_string
from saml2.validate import valid_instance


class FakeSP(Saml2Client):
    def __init__(self, config_module, config=None):
        if config is None:
            config = config_factory('sp', config_module)
        Saml2Client.__init__(self, config)

    def make_auth_req(self, entity_id):
        # Picks a binding to use for sending the Request to the IDP
        _binding, destination = self.pick_binding(
            'single_sign_on_service',
            [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST], 'idpsso',
            entity_id=entity_id)
        # Binding here is the response binding that is which binding the
        # IDP shou  ld use to return the response.
        acs = self.config.getattr('endpoints', 'sp')[
            'assertion_consumer_service']
        # just pick one
        for i in range(len(acs)):
            endp, return_binding = acs[i]
            if return_binding == _binding:
                break

        req_id, req = self.create_authn_request(destination,
                                                binding=return_binding)
        ht_args = self.apply_binding(_binding, '%s' % req, destination,
                                     relay_state='hello')

        url = ht_args['headers'][0][1]
        return url


class FakeIdP(server.Server):
    def __init__(self, user_db):
        server.Server.__init__(self, 'configurations.idp_conf')
        self.user_db = user_db

    def handle_auth_req(self, saml_request, relay_state, binding, userid):
        auth_req = self.parse_authn_request(saml_request, binding)
        binding_out, destination = self.pick_binding(
            'assertion_consumer_service',
            entity_id=auth_req.message.issuer.text, request=auth_req.message)

        resp_args = self.response_args(auth_req.message)
        authn_broker = AuthnBroker()
        authn_broker.add(authn_context_class_ref(PASSWORD), lambda: None, 10,
                         'unittest_idp.xml')
        authn_broker.get_authn_by_accr(PASSWORD)
        resp_args['authn'] = authn_broker.get_authn_by_accr(PASSWORD)

        _resp = self.create_authn_response(self.user_db[userid],
                                           userid=userid,
                                           **resp_args)

        http_args = self.apply_binding(BINDING_HTTP_POST, '%s' % _resp,
                                       destination, relay_state, response=True)
        url = http_args['url']
        saml_response = base64.b64encode(str(_resp).encode("utf-8"))
        resp = {'SAMLResponse': saml_response, 'RelayState': relay_state}
        return url, resp


def generate_cert():
    sn = random.randint(1, sys.maxsize)
    cert_info = {
        "cn": "localhost",
        "country_code": "se",
        "state": "ac",
        "city": "Umea",
        "organization": "ITS",
        "organization_unit": "DIRG"
    }
    osw = OpenSSLWrapper()
    cert_str, key_str = osw.create_certificate(cert_info, request=False, sn=sn, key_length=2048)
    cert_file = tempfile.NamedTemporaryFile()
    cert_file.write(cert_str)
    cert_file.flush()
    key_file = tempfile.NamedTemporaryFile()
    key_file.write(key_str)
    key_file.flush()
    return cert_file, key_file


def create_name_id():
    TEST_NAME_ID = """<?xml version="1.0" encoding="utf-8"?>
<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
  Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  SPProvidedID="sp provided id">
  tmatsuo@example.com
</NameID>
"""
    return name_id_from_string(TEST_NAME_ID)


def create_metadata(config):
    nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
    eds = []

    conf = Config().load(config, metadata_construction=True)
    eds.append(entity_descriptor(conf))
    ed_id = conf.entityid

    desc, xmldoc = entities_descriptor(eds, conf.valid_for, None, ed_id, False, None)
    valid_instance(desc)
    tmp_file = tempfile.NamedTemporaryFile()
    tmp_file.write(desc.to_string(nspair))
    tmp_file.flush()
    return tmp_file
