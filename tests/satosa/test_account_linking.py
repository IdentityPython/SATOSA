from mock.mock import MagicMock
import pytest
import responses

from satosa.account_linking import AccountLinkingModule
from satosa.context import Context
from satosa.internal_data import InternalResponse, AuthenticationInformation
from satosa.response import Redirect
from satosa.satosa_config import SATOSAConfig
from satosa.state import State
from tests.util import FileGenerator, private_to_public_key

__author__ = 'danielevertsson'

INTERNAL_ATTRIBUTES = {
    'attributes': {
        'displayname': {
            'openid': ['nickname'], 'saml': ['displayName']
        },
        'givenname': {
            'saml': ['givenName'], 'openid': ['given_name'],
            'facebook': ['first_name']
        },
        'mail': {
            'saml': ['email', 'emailAdress', 'mail'], 'openid': ['email'],
            'facebook': ['email']
        },
        'edupersontargetedid': {
            'saml': ['eduPersonTargetedID'], 'openid': ['sub'],
            'facebook': ['id']
        },
        'name': {
            'saml': ['cn'], 'openid': ['name'], 'facebook': ['name']
        },
        'address': {
            'openid': ['address->street_address'], 'saml': ['postaladdress']
        },
        'surname': {
            'saml': ['sn', 'surname'], 'openid': ['family_name'],
            'facebook': ['last_name']
        }
    }, 'separator': '->'
}

CONSENT_CERT, CONSENT_KEY = FileGenerator.get_instance().generate_cert("consent")
CONSENT_PUB_KEY_STR = private_to_public_key(CONSENT_KEY.name)


class TestAccountLinking():
    @pytest.fixture(autouse=True)
    def setup(self):
        self.account_linking_config = {
            "enable": True,
            "rest_uri": "https://localhost:8167",
            "redirect": "https://localhost:8167/approve",
            "endpoint": "handle_account_linking",
            "sign_key": CONSENT_KEY.name,
            "verify_ssl": False
        }
        self.satosa_config = {
            "BASE": "https://proxy.example.com",
            "USER_ID_HASH_SALT": "qwerty",
            "COOKIE_STATE_NAME": "SATOSA_SATE",
            "STATE_ENCRYPTION_KEY": "ASDasd123",
            "PLUGIN_PATH": "",
            "BACKEND_MODULES": "",
            "FRONTEND_MODULES": "",
            "INTERNAL_ATTRIBUTES": INTERNAL_ATTRIBUTES,
            "ACCOUNT_LINKING": self.account_linking_config
        }
        self.callback_func = MagicMock()
        self.context = Context()
        state = State()
        self.context.state = state
        auth_info = AuthenticationInformation("auth_class_ref", "timestamp", "issuer")
        self.internal_response = InternalResponse(auth_info=auth_info)

    def test_disable_account_linking(self):
        self.account_linking_config['enable'] = False
        config = SATOSAConfig(self.satosa_config)
        account_linking = AccountLinkingModule(config, self.callback_func)
        account_linking.manage_al(None, None)
        assert self.callback_func.called

    @responses.activate
    def test_store_existing_uuid_in_internal_attributes(self):
        uuid = "uuid"
        responses.add(
            responses.GET,
            "%s/get_id" % self.account_linking_config['rest_uri'],
            status=200,
            body=uuid,
            content_type='text/html'
        )
        account_linking = AccountLinkingModule(
            SATOSAConfig(self.satosa_config),
            self.callback_func
        )
        account_linking.manage_al(self.context, self.internal_response)
        assert self.internal_response.get_user_id() == uuid

    @responses.activate
    def test_account_link_does_not_exists(self):
        ticket = "ticket"
        responses.add(
            responses.GET,
            "%s/get_id" % self.account_linking_config['rest_uri'],
            status=400,
            body=ticket,
            content_type='text/html'
        )
        account_linking = AccountLinkingModule(
            SATOSAConfig(self.satosa_config),
            self.callback_func
        )
        result = account_linking.manage_al(self.context, self.internal_response)
        assert isinstance(result, Redirect)
        assert self.account_linking_config["redirect"] in result.message
