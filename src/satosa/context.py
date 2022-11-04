from warnings import warn as _warn

from satosa.exception import SATOSABadContextError


def get_auth_req_params(context):
    return context.state.get(Context.KEY_AUTH_REQ_PARAMS) or context.get_decoration(Context.KEY_AUTH_REQ_PARAMS) or {}


def get_prompt_list(context):
    auth_req_params = get_auth_req_params(context)
    prompt = auth_req_params.get(Context.KEY_PROMPT, "")
    return prompt if isinstance(prompt, list) else prompt.split(" ")


def prompt_to_saml_param(context, saml_param):
    prompt_list = get_prompt_list(context)
    if saml_param == Context.KEY_SAML_IS_PASSIVE:
        return "none" in prompt_list
    # there is no standard way to force only account selection in SAML, force new login instead
    if saml_param == Context.KEY_SAML_FORCE_AUTHN:
        return "select_account" in prompt_list or "login" in prompt_list


def add_prompt_to_context(context, prompt_value):
    state_auth_req_params = context.state.get(Context.KEY_AUTH_REQ_PARAMS) or {}
    context_auth_req_params = context.get_decoration(Context.KEY_AUTH_REQ_PARAMS) or {}
    state_auth_req_params["prompt"] = prompt_value
    context_auth_req_params["prompt"] = prompt_value
    context.state[Context.KEY_AUTH_REQ_PARAMS] = state_auth_req_params
    context.decorate(Context.KEY_AUTH_REQ_PARAMS, context_auth_req_params)


def get_deprecated_context_key(old_key, new_key):
    msg = "'{old_key}' is deprecated; use '{new_key}' instead.".format(
        old_key=old_key, new_key=new_key
    )
    _warn(msg, DeprecationWarning)
    return getattr(Context, new_key)

class Context(object):
    """
    Holds methods for sharing proxy data through the current request
    """
    KEY_METADATA_STORE = 'metadata_store'
    KEY_TARGET_ENTITYID = 'target_entity_id'
    KEY_SAML_FORCE_AUTHN = 'force_authn'
    KEY_SAML_IS_PASSIVE = 'is_passive'
    KEY_MEMORIZED_IDP = 'memorized_idp'
    KEY_REQUESTER_METADATA = 'requester_metadata'
    KEY_AUTHN_CONTEXT_CLASS_REF = 'authn_context_class_ref'
    KEY_TARGET_AUTHN_CONTEXT_CLASS_REF = 'target_authn_context_class_ref'
    KEY_AUTH_REQ_PARAMS = 'auth_req_params'
    KEY_PROMPT = 'prompt'

    def __init__(self):
        self._path = None
        self.request = None
        self.request_uri = None
        self.request_method = None
        self.qs_params = None
        self.server = None
        self.http_headers = None
        self.cookie = None
        self.request_authorization = None
        self.target_backend = None
        self.target_frontend = None
        self.target_micro_service = None
        # This dict is a data carrier between frontend and backend modules.
        self.internal_data = {}
        self.state = None

    @property
    def KEY_BACKEND_METADATA_STORE(self):
        return get_deprecated_context_key("KEY_BACKEND_METADATA_STORE", "KEY_METADATA_STORE")

    @property
    def path(self):
        """
        Get the path

        :rtype: str

        :return: context path
        """
        return self._path

    @path.setter
    def path(self, p):
        """
        Inserts a path to the context.
        This path is striped by the base_url, so for example:
            A path BASE_URL/ENDPOINT_URL, would be inserted as only ENDPOINT_URL
            https://localhost:8092/sso/redirect -> sso/redirect

        :type p: str

        :param p: A path to an endpoint.
        :return: None
        """
        if not p:
            raise ValueError("path can't be set to None")
        elif p.startswith('/'):
            raise ValueError("path can't start with '/'")
        self._path = p

    def target_entity_id_from_path(self):
        target_entity_id = self.path.split("/")[1]
        return target_entity_id

    def decorate(self, key, value):
        """
        Add information to the context
        """

        self.internal_data[key] = value
        return self

    def get_decoration(self, key):
        """
        Retrieve information from the context
        """

        value = self.internal_data.get(key)
        return value
