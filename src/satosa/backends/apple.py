"""
Apple backend module.
"""
import logging
from .openid_connect import OpenIDConnectBackend, STATE_KEY
from oic.oauth2.message import Message
from oic.oic.message import AuthorizationResponse
import satosa.logging_util as lu
from ..exception import SATOSAAuthenticationError
import json
import requests


logger = logging.getLogger(__name__)


# https://developer.okta.com/blog/2019/06/04/what-the-heck-is-sign-in-with-apple
class AppleBackend(OpenIDConnectBackend):
    """Sign in with Apple backend"""

    def _get_tokens(self, authn_response, context):
        """
        :param authn_response: authentication response from OP
        :type authn_response: oic.oic.message.AuthorizationResponse
        :return: access token and ID Token claims
        :rtype: Tuple[Optional[str], Optional[Mapping[str, str]]]
        """
        if "code" in authn_response:
            # make token request
            # https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
            args = {
                "client_id": self.client.client_id,
                "client_secret": self.client.client_secret,
                "code": authn_response["code"],
                "grant_type": "authorization_code",
                "redirect_uri": self.client.registration_response["redirect_uris"][0],
            }

            token_resp = requests.post(
                "https://appleid.apple.com/auth/token",
                data=args,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ).json()

            logger.debug("apple response received")
            logger.debug(token_resp)

            self._check_error_response(token_resp, context)

            keyjar = self.client.keyjar
            id_token_claims = dict(
                Message().from_jwt(token_resp["id_token"], keyjar=keyjar)
            )

            return token_resp["access_token"], id_token_claims

        return authn_response.get("access_token"), authn_response.get("id_token")

    def response_endpoint(self, context, *args):
        """
        Handles the authentication response from the OP.
        :type context: satosa.context.Context
        :type args: Any
        :rtype: satosa.response.Response

        :param context: SATOSA context
        :param args: None
        :return:
        """
        backend_state = context.state[self.name]

        # Apple has no userinfo endpoint
        # but may send some user information via POST in the first request.
        #
        # References:
        # - https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
        # - https://developer.apple.com/documentation/sign_in_with_apple/namei
        try:
            userdata = context.request.get("user", "{}")
            userinfo = json.loads(userdata)
        except json.JSONDecodeError:
            userinfo = {}

        authn_resp = self.client.parse_response(
            AuthorizationResponse, info=context.request, sformat="dict"
        )
        if backend_state[STATE_KEY] != authn_resp["state"]:
            msg = "Missing or invalid state in authn response for state: {}".format(
                backend_state
            )
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.debug(logline)
            raise SATOSAAuthenticationError(
                context.state, "Missing or invalid state in authn response"
            )

        self._check_error_response(authn_resp, context)
        access_token, id_token_claims = self._get_tokens(authn_resp, context)
        if not id_token_claims:
            id_token_claims = {}

        if not id_token_claims and not userinfo:
            msg = "No id_token or userinfo, nothing to do.."
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, "No user info available.")

        all_user_claims = dict(list(userinfo.items()) + list(id_token_claims.items()))

        # convert "string or Boolean" claims to actual booleans
        for bool_claim_name in ["email_verified", "is_private_email"]:
            if type(all_user_claims.get(bool_claim_name)) == str:
                all_user_claims[bool_claim_name] = (
                    True if all_user_claims[bool_claim_name] == "true" else False
                )

        msg = "UserInfo: {}".format(all_user_claims)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        internal_resp = self._translate_response(
            all_user_claims, self.client.authorization_endpoint
        )
        return self.auth_callback_func(context, internal_resp)
