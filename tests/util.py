"""
Contains help methods and classes to perform tests.
"""
import base64
import json
import tempfile
from urllib.parse import parse_qsl, urlparse

from Crypto.PublicKey import RSA
from saml2 import server, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.authn_context import AuthnBroker, authn_context_class_ref, PASSWORD
from saml2.cert import OpenSSLWrapper
from saml2.client import Saml2Client
from saml2.config import config_factory, Config
from saml2.metadata import entity_descriptor
from saml2.saml import name_id_from_string, NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT
from saml2.samlp import NameIDPolicy

from satosa.backends.base import BackendModule
from satosa.frontends.base import FrontendModule
from satosa.micro_services.base import RequestMicroService, ResponseMicroService
from satosa.response import Response


class FakeSP(Saml2Client):
    """
    A SAML service provider that can be used to perform tests.
    """

    def __init__(self, config):
        """
        :type config: {dict}
        :param config: SP SAML configuration.
        """
        Saml2Client.__init__(self, config)

    def make_auth_req(self, entity_id, nameid_format=None, relay_state="relay_state", binding=BINDING_HTTP_REDIRECT):
        """
        :type entity_id: str
        :rtype: str

        :param entity_id: SAML entity id
        :return: Authentication URL.
        """
        # Picks a binding to use for sending the Request to the IDP
        _binding, destination = self.pick_binding(
            'single_sign_on_service',
            [binding], 'idpsso',
            entity_id=entity_id)
        # Binding here is the response binding that is which binding the
        # IDP shou  ld use to return the response.
        acs = self.config.getattr('endpoints', 'sp')[
            'assertion_consumer_service']
        # just pick one
        return_binding = None
        for i in range(len(acs)):
            endp, return_binding = acs[i]
            if return_binding == _binding:
                break

        req_id, req = self.create_authn_request(destination,
                                                binding=return_binding, nameid_format=nameid_format)
        ht_args = self.apply_binding(_binding, '%s' % req, destination,
                                     relay_state=relay_state)

        url = ht_args['headers'][0][1]
        return url


class FakeIdP(server.Server):
    """
    A SAML IdP that can be used to perform tests.
    """

    def __init__(self, user_db, config):
        """
        :type user_db: {dict}
        :type config: {dict}

        :param user_db: A dictionary with the user id as key and parameter dictionary as value.
        :param config: IdP SAML configuration.
        """
        server.Server.__init__(self, config=config)
        self.user_db = user_db

    def handle_auth_req(self, saml_request, relay_state, binding, userid,
                        response_binding=BINDING_HTTP_POST):
        """
        Handles a SAML request, validates and creates a SAML response.
        :type saml_request: str
        :type relay_state: str
        :type binding: str
        :type userid: str
        :rtype:

        :param saml_request:
        :param relay_state: RelayState is a parameter used by some SAML protocol implementations to
        identify the specific resource at the resource provider in an IDP initiated single sign on
        scenario.
        :param binding:
        :param userid: The user identification.
        :return: A tuple with
        """
        auth_req = self.parse_authn_request(saml_request, binding)
        binding_out, destination = self.pick_binding(
            'assertion_consumer_service',
            bindings=[response_binding],
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

        if response_binding == BINDING_HTTP_POST:
            saml_response = base64.b64encode(str(_resp).encode("utf-8"))
            resp = {'SAMLResponse': saml_response, 'RelayState': relay_state}
        elif response_binding == BINDING_HTTP_REDIRECT:
            http_args = self.apply_binding(response_binding, '%s' % _resp,
                                           destination, relay_state, response=True)
            resp = dict(parse_qsl(urlparse(dict(http_args["headers"])["Location"]).query))

        return destination, resp


def create_metadata_from_config_dict(config):
    nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
    conf = Config().load(config, metadata_construction=True)
    return entity_descriptor(conf).to_string(nspair).decode("utf-8")


def generate_cert():
    cert_info = {
        "cn": "localhost",
        "country_code": "se",
        "state": "ac",
        "city": "Umea",
        "organization": "ITS",
        "organization_unit": "DIRG"
    }
    osw = OpenSSLWrapper()
    cert_str, key_str = osw.create_certificate(cert_info, request=False)
    return cert_str, key_str


def write_cert(cert_path, key_path):
    cert, key = generate_cert()
    with open(cert_path, "wb") as cert_file:
        cert_file.write(cert)
    with open(key_path, "wb") as key_file:
        key_file.write(key)


class FileGenerator(object):
    """
    Creates different types of temporary files that is useful for testing.
    """
    _instance = None

    def __init__(self):
        if FileGenerator._instance:
            raise TypeError('Singletons must be accessed through `get_instance()`.')
        else:
            FileGenerator._instance = self
        self.generate_certs = {}
        self.metadata = {}

    @staticmethod
    def get_instance():
        """
        :rtype: FileGenerator

        :return: A singleton instance of the class.
        """
        if FileGenerator._instance is None:
            FileGenerator._instance = FileGenerator()
        return FileGenerator._instance

    def generate_cert(self, code=None):
        """
        Will generate a certificate and key. If code is used the same certificate and key will
        always be returned for the same code.
        :type code: str
        :rtype: (tempfile._TemporaryFileWrapper, tempfile._TemporaryFileWrapper)

        :param: code: A unique code to represent a certificate and key.
        :return: A certificate and key temporary file.
        """
        if code in self.generate_certs:
            return self.generate_certs[code]

        cert_str, key_str = generate_cert()

        cert_file = tempfile.NamedTemporaryFile()
        cert_file.write(cert_str)
        cert_file.flush()
        key_file = tempfile.NamedTemporaryFile()
        key_file.write(key_str)
        key_file.flush()
        if code is not None:
            self.generate_certs[code] = cert_file, key_file
        return cert_file, key_file

    def create_metadata(self, config, code=None):
        """
        Will generate a metadata file. If code is used the same metadata file will
        always be returned for the same code.
        :type config: {dict}
        :type code: str

        :param config: A SAML configuration.
        :param code: A unique code to represent a certificate and key.
        """
        if code in self.metadata:
            return self.metadata[code]

        desc = create_metadata_from_config_dict(config)

        tmp_file = tempfile.NamedTemporaryFile()
        tmp_file.write(desc.encode("utf-8"))
        tmp_file.flush()
        if code:
            self.metadata[code] = tmp_file
        return tmp_file


def private_to_public_key(pk_file):
    f = open(pk_file, 'r')
    pk = RSA.importKey(f.read())
    return pk.publickey().exportKey('PEM')


def create_name_id():
    """
    :rtype: str

    :return: Returns a SAML nameid as XML string.
    """
    test_name_id = """<?xml version="1.0" encoding="utf-8"?>
<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
  Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  SPProvidedID="sp provided id">
  tmatsuo@example.com
</NameID>
"""
    return name_id_from_string(test_name_id)


def create_name_id_policy_transient():
    """
    Creates a transient name id policy.
    :return:
    """
    nameid_format = NAMEID_FORMAT_TRANSIENT
    name_id_policy = NameIDPolicy(format=nameid_format)
    return name_id_policy


def create_name_id_policy_persistent():
    """
    Creates a transient name id policy.
    :return:
    """
    nameid_format = NAMEID_FORMAT_PERSISTENT
    name_id_policy = NameIDPolicy(format=nameid_format)
    return name_id_policy


class FakeBackend(BackendModule):
    def __init__(self, start_auth_func=None, internal_attributes=None,
                 base_url="", name="FakeBackend",
                 register_endpoints_func=None):
        super().__init__(None, internal_attributes, base_url, name)

        self.start_auth_func = start_auth_func
        self.register_endpoints_func = register_endpoints_func

    def start_auth(self, context, request_info, state):
        """
        TODO comment
        :type context: TODO comment
        :type request_info: TODO comment
        :type state: TODO comment

        :param context: TODO comment
        :param request_info: TODO comment
        :param state: TODO comment
        """
        if self.start_auth:
            return self.start_auth(context, request_info, state)
        return None

    def register_endpoints(self):
        """
        TODO comment
        """
        if self.register_endpoints_func:
            return self.register_endpoints_func()
        return None


class FakeFrontend(FrontendModule):
    """
    TODO comment
    """

    def __init__(self, handle_authn_request_func=None, internal_attributes=None,
                 base_url="", name="FakeFrontend",
                 handle_authn_response_func=None,
                 register_endpoints_func=None):
        super().__init__(None, internal_attributes, base_url, name)
        self.handle_authn_request_func = handle_authn_request_func
        self.handle_authn_response_func = handle_authn_response_func
        self.register_endpoints_func = register_endpoints_func

    def handle_authn_request(self, context, binding_in):
        """
        TODO comment

        :type context:
        :type binding_in:

        :param context:
        :param binding_in:
        :return:
        """
        if self.handle_authn_request_func:
            return self.handle_authn_request_func(context, binding_in)
        return None

    def handle_authn_response(self, context, internal_response, state):
        """
        TODO comment
        :type context: TODO comment
        :type internal_response: TODO comment
        :type state: TODO comment

        :param context: TODO  comment
        :param internal_response: TODO comment
        :param state: TODO comment
        :return: TODO comment
        """
        if self.handle_authn_response_func:
            return self.handle_authn_response_func(context, internal_response, state)
        return None

    def register_endpoints(self, backend_names):
        if self.register_endpoints_func:
            return self.register_endpoints_func(backend_names)


class TestBackend(BackendModule):
    def __init__(self, auth_callback_func, internal_attributes, config, base_url, name):
        super().__init__(auth_callback_func, internal_attributes, base_url, name)

    def register_endpoints(self):
        return [("^{}/response$".format(self.name), self.handle_response)]

    def handle_response(self, context):
        return Response(json.dumps({"foo": "bar"}))


class TestFrontend(FrontendModule):
    def __init__(self, auth_req_callback_func, internal_attributes, config, base_url, name):
        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)

    def register_endpoints(self, backend_names):
        url_map = [("^{}/{}/request$".format(p, self.name), self.handle_request) for p in backend_names]
        return url_map

    def handle_request(self, context):
        return Response('Request received OK')


class TestRequestMicroservice(RequestMicroService):
    def process(self, context, data):
        return data


class TestResponseMicroservice(ResponseMicroService):
    def process(self, context, data):
        return data
