import base64

from saml2 import server, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.authn_context import AuthnBroker, authn_context_class_ref, PASSWORD
from saml2.client import Saml2Client
from saml2.config import config_factory


class TestSP(Saml2Client):
    def __init__(self, config_module):
        Saml2Client.__init__(self, config_factory('sp', config_module))

    def make_auth_req(self):
        # Picks a binding to use for sending the Request to the IDP
        _binding, destination = self.pick_binding(
            'single_sign_on_service',
            [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST], 'idpsso',
            entity_id='https://example.com/proxy.xml')
        # Binding here is the response binding that is which binding the
        # IDP shou  ld use to return the response.
        acs = self.config.getattr('endpoints', 'sp')[
            'assertion_consumer_service']
        # just pick one
        endp, return_binding = acs[0]

        req_id, req = self.create_authn_request(destination,
                                                binding=return_binding)
        ht_args = self.apply_binding(_binding, '%s' % req, destination,
                                     relay_state='hello')

        url = ht_args['headers'][0][1]
        return url


class TestIdP(server.Server):
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
        saml_response = base64.b64encode(str(_resp))
        resp = {'SAMLResponse': saml_response, 'RelayState': relay_state}
        return url, resp