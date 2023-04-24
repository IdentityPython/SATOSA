from typing import Any, Optional
from warnings import warn as _warn

from satosa.exception import SATOSAError


class SATOSABadContextError(SATOSAError):
    """
    Raise this exception if validating the Context and failing.
    """

    pass


class Context(object):
    """
    Holds methods for sharing proxy data through the current request
    """

    KEY_METADATA_STORE = "metadata_store"
    KEY_TARGET_ENTITYID = "target_entity_id"
    KEY_FORCE_AUTHN = "force_authn"
    KEY_MEMORIZED_IDP = "memorized_idp"
    KEY_AUTHN_CONTEXT_CLASS_REF = "authn_context_class_ref"
    KEY_TARGET_AUTHN_CONTEXT_CLASS_REF = "target_authn_context_class_ref"

    def __init__(self) -> None:
        self._path: Optional[str] = None
        self.request: dict[str, Any] = None
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
        self.internal_data: dict[str, Any] = {}
        self.state: dict[str, Any] = {}

    @property
    def KEY_BACKEND_METADATA_STORE(self):
        msg = "'{old_key}' is deprecated; use '{new_key}' instead.".format(
            old_key="KEY_BACKEND_METADATA_STORE", new_key="KEY_METADATA_STORE"
        )
        _warn(msg, DeprecationWarning)
        return Context.KEY_METADATA_STORE

    @property
    def path(self) -> Optional[str]:
        """
        Get the path

        :return: context path
        """
        return self._path

    @path.setter
    def path(self, p: str) -> None:
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
        elif p.startswith("/"):
            raise ValueError("path can't start with '/'")
        self._path = p

    def target_entity_id_from_path(self) -> Optional[str]:
        target_entity_id = self.path.split("/")[1]
        return target_entity_id

    def decorate(self, key: str, value: Any) -> "Context":
        """
        Add information to the context
        """
        self.internal_data[key] = value
        return self

    def get_decoration(self, key: str) -> Any:
        """
        Retrieve information from the context
        """

        value = self.internal_data.get(key)
        return value
