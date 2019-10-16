"""
ADFS/SAML-Support for role selection and profile completion after a SAML-Response
was issued using a redirect-to-idp flow.
* Store AuthnRequest for later replay
* Handle redirect-to-idp and replay AuthnRequest after redirect-to-idp flow

Persist state: Storing the the full context of the AuthnRequest in SATOSA_STATE is not feasible due to cookie size limitations.
Instead, it is stored in a local redis store, and the key is stored in SATOSA_STATE.

The Redis interface is using a basic implementation creating a connection pool and TCP sockets for each call, which is OK for the modest deployment.
(Instantiating a global connection pool across gunicorn worker threads would impose some additional complexity.)
The AuthnRequest is stored unencrypted with the assumption that a stolen request cannot do harm,
because the final Response will only be delivered to the metadata-specified ACS endpoint.


"""

import logging
import sys
from typing import Tuple
import satosa
from .base import RequestMicroService, ResponseMicroService
from satosa.micro_services.local_store import LocalStore

MIN_PYTHON = (3, 6)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

STATE_KEY = "REDIRURLCONTEXT"


class RedirectUrlRequest(RequestMicroService):
    """ Store AuthnRequest in SATOSA STATE in case it is required later for the RedirectUrl flow """
    def __init__(self, config: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.local_store = LocalStore(config['db_encryption_key'], redishost=config.get('redis_host', 'localhost'))
        logging.info('RedirectUrlRequest microservice active')

    def process(self, context: satosa.context.Context, internal_request: satosa.internal.InternalData) \
            -> Tuple[satosa.context.Context, satosa.internal.InternalData]:
        key = self.local_store.set(context)
        context.state[STATE_KEY] = str(key)
        logging.debug(f"RedirectUrlRequest: store context (stub)")
        return super().process(context, internal_request)


class RedirectUrlResponse(ResponseMicroService):
    """
    Handle following events:
    * Processing a SAML Response:
        if the redirectUrl attribute is set in the response/attribute statement:
            Redirect to responder
    * Processing a RedirectUrlResponse:
        Retrieve previously saved AuthnRequest
        Replay AuthnRequest
    """
    def __init__(self, config: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.endpoint = 'redirecturl_response'
        self.self_entityid = config['self_entityid']
        self.redir_attr = config['redirect_attr_name']
        self.redir_entityid = config['redir_entityid']
        self.local_store = LocalStore(config['db_encryption_key'], redishost=config.get('redis_host', 'localhost'))
        logging.info('RedirectUrlResponse microservice active')

    def _handle_redirecturl_response(
            self,
            context: satosa.context.Context,
            wsgi_app: callable(satosa.context.Context)) -> satosa.response.Response:
        logging.debug(f"RedirectUrl microservice: RedirectUrl processing complete")
        key = int(context.state[STATE_KEY])
        authnrequ_context = self.local_store.get(key)
        resp = wsgi_app.run(authnrequ_context)
        return resp

    def process(self, context: satosa.context.Context,
                internal_response: satosa.internal.InternalData) -> satosa.response.Response:
        if self.redir_attr in internal_response.attributes:
            logging.debug(f"RedirectUrl microservice: Attribute {self.redir_attr} found, starting redirect")
            redirecturl = internal_response.attributes[self.redir_attr][0] + '?wtrealm=' + self.self_entityid
            return satosa.response.Redirect(redirecturl)
        else:
            logging.debug(f"RedirectUrl microservice: Attribute {self.redir_attr} not found")
        return super().process(context, internal_response)

    def register_endpoints(self):
        return [("^{}$".format(self.endpoint), self._handle_redirecturl_response), ]


if sys.version_info < (3, 6):
    raise Exception("Must be using Python 3.6 or later")
