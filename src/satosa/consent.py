import json
import requests
from base64 import urlsafe_b64encode, urlsafe_b64decode
from saml2.httputil import Redirect, Response
from satosa.internal_data import InternalResponse, AuthenticationInformation, UserIdHashType

__author__ = 'mathiashedstrom'


class ConsentModule(object):
    def __init__(self, config, callback_func):
        self.callback_func = callback_func
        self.enabled = "CONSENT" in config and ("enable" not in config.CONSENT or config.CONSENT["enable"])
        if self.enabled:
            self.check_consent_url = config.CONSENT["service.check"]
            self.consent_interaction = config.CONSENT["service.interaction"]
            self.endpoint = config.CONSENT["endpoint"]

    def save_state(self, internal_request, state):
        if self.enabled:
            state = {"state": state, "filter": internal_request._attribute_filter}
            state = urlsafe_b64encode(json.dumps(state).encode("utf-8")).decode("utf-8")
        return state

    def _handle_consent_response(self, context):
        # Handle answer from consent service
        consent_was_given = context.request["consent"]
        if consent_was_given:
            # load state
            state = json.loads(urlsafe_b64decode(context.request["state"].encode("utf-8")).decode("utf-8"))

            # rebuild internal_response from state
            auth_info = AuthenticationInformation(state["auth_info"]["auth_class_ref"], state["auth_info"]["timestamp"],
                                                  state["auth_info"]["issuer"])
            internal_response = InternalResponse(getattr(UserIdHashType, state["hash_type"]), auth_info=auth_info)
            internal_response._attributes = state["attr"]
            internal_response.user_id = state["usr_id"]
            state = state["state"]
            return self.callback_func(context, internal_response, state)
        else:
            return Response(message="consent NOT given")

    def check_consent(self, context, internal_response, state):

        if not self.enabled:
            return self.callback_func(context, internal_response, state)

        state = json.loads(urlsafe_b64decode(state).decode("utf-8"))
        filter = state["filter"]
        state = state["state"]

        # filter attributes

        filtered_attributes = []
        for attr in filter:
            if attr in internal_response._attributes:
                filtered_attributes.append(attr)

        all_attributes = urlsafe_b64encode(json.dumps(filtered_attributes).encode("utf-8")).decode("utf-8")
        # Check against consent service if consent is given or not
        try:
            request = "%s?attr=%s&uid=%s" % (self.check_consent_url, all_attributes, internal_response.user_id)
            res = requests.get(request, verify=False)
            result = json.loads(res.text)
        except ConnectionError as con_exc:
            raise ConnectionError(
                "Could not connect to consent service: {}".format(str(con_exc)))

        # update internal response
        filtered_data = {}
        for attr in filtered_attributes:
            filtered_data[attr] = internal_response._attributes[attr]
        internal_response._attributes = filtered_data

        # Check if consent is already given
        if result["result"]:
            return self.callback_func(context, internal_response, state)

        # save state
        response_state = self._internal_resp_to_state(internal_response, state)

        # redirect to consent service
        return Redirect("%s?state=%s" % (self.consent_interaction, response_state))

    def _internal_resp_to_state(self, internal_response, state):
        # TODO move to InternalResponse
        auth_info = internal_response.auth_info
        response_state = {"state": state,
                          "usr_id": internal_response.user_id,
                          "attr": internal_response._attributes,
                          "hash_type": internal_response.user_id_hash_type.name,
                          "auth_info": {"issuer": auth_info.issuer,
                                        "timestamp": auth_info.timestamp,
                                        "auth_class_ref": auth_info.auth_class_ref, }}
        return urlsafe_b64encode(json.dumps(response_state).encode("utf-8")).decode("utf-8")

    def register_endpoints(self):
        return [("^consent/%s?(.*)$" % self.endpoint, self._handle_consent_response)]
