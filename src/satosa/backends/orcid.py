"""
OAuth backend for Orcid
"""
import json
import requests
import logging
from urllib.parse import urljoin

from oic.utils.authn.authn_context import UNSPECIFIED
from oic.oauth2.consumer import stateID
from oic.oauth2.message import AuthorizationResponse

from satosa.backends.oauth import _OAuthBackend
from ..internal_data import InternalResponse
from ..internal_data import AuthenticationInformation
from ..response import Redirect

logger = logging.getLogger(__name__)


class OrcidBackend(_OAuthBackend):
    """Orcid OAuth 2.0 backend"""

    def __init__(self, outgoing, internal_attributes, config, base_url, name):
        """Orcid backend constructor
        :param outgoing: Callback should be called by the module after the
            authorization in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal
            attribute names and the names returned by underlying IdP's/OP's as
            well as what attributes the calling SP's and RP's expects namevice.
        :param config: configuration parameters for the module.
        :param base_url: base url of the service
        :param name: name of the plugin
        :type outgoing:
            (satosa.context.Context, satosa.internal_data.InternalResponse) ->
            satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type config: dict[str, dict[str, str] | list[str] | str]
        :type base_url: str
        :type name: str
        """
        config.setdefault('response_type', 'code')
        config['verify_accesstoken_state'] = False
        super().__init__(
            outgoing, internal_attributes, config, base_url, name, 'orcid',
            'orcid')

    def start_auth(self, context, internal_request, get_state=stateID):
        """
        :param get_state: Generates a state to be used in authentication call

        :type get_state: Callable[[str, bytes], str]
        :type context: satosa.context.Context
        :type internal_request: satosa.internal_data.InternalRequest
        :rtype satosa.response.Redirect
        """
        request_args = dict(
            client_id=self.config['client_config']['client_id'],
            redirect_uri=self.redirect_url,
            scope=' '.join(self.config['scope']), )
        cis = self.consumer.construct_AuthorizationRequest(
            request_args=request_args)
        return Redirect(cis.request(self.consumer.authorization_endpoint))

    def auth_info(self, requrest):
        return AuthenticationInformation(
            UNSPECIFIED, None,
            self.config['server_info']['authorization_endpoint'])

    def _authn_response(self, context):
        aresp = self.consumer.parse_response(
            AuthorizationResponse, info=json.dumps(context.request))
        url = self.config['server_info']['token_endpoint']
        data = dict(
            grant_type='authorization_code',
            code=aresp['code'],
            redirect_uri=self.redirect_url,
            client_id=self.config['client_config']['client_id'],
            client_secret=self.config['client_secret'], )
        headers = {'Accept': 'application/json'}

        r = requests.post(url, data=data, headers=headers)
        response = r.json()
        token = response['access_token']
        orcid, name = response['orcid'], response['name']
        user_info = self.user_information(token, orcid, name)
        auth_info = self.auth_info(context.request)
        internal_response = InternalResponse(auth_info=auth_info)
        internal_response.attributes = self.converter.to_internal(
            self.external_type, user_info)
        internal_response.user_id = orcid
        return self.auth_callback_func(context, internal_response)

    def user_information(self, access_token, orcid, name):
        base_url = self.config['server_info']['user_info']
        url = urljoin(base_url, '{}/person'.format(orcid))
        headers = {
            'Accept': 'application/orcid+json',
            'Authorization type': 'Bearer',
            'Access token': access_token,
        }
        r = requests.get(url, headers=headers)
        r = r.json()
        emails, addresses = r['emails']['email'], r['addresses']['address']
        ret = dict(
            address=', '.join([e['address'] for e in addresses]),
            displayname=name,
            edupersontargetedid=orcid, orcid=orcid,
            mail=' '.join([e['email'] for e in emails]),
            name=name,
            givenname=r['name']['given-names']['value'],
            surname=r['name']['family-name']['value'],
        )
        return ret
