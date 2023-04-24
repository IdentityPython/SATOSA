"""Internal data representation for SAML/OAuth/OpenID connect."""
from __future__ import annotations

from typing import Any, Mapping, NewType, Optional, Type, TypeVar
import warnings as _warnings
from collections import UserDict

TDatafySubclass = TypeVar("TDatafySubclass", bound="_Datafy")


class _Datafy(UserDict):
    _DEPRECATED_TO_NEW_MEMBERS: Mapping[str, str] = {}

    def _get_new_key(self, old_key):
        new_key = self.__class__._DEPRECATED_TO_NEW_MEMBERS.get(old_key, old_key)
        is_key_deprecated = old_key != new_key
        if is_key_deprecated:
            msg = "'{old_key}' is deprecated; use '{new_key}' instead.".format(old_key=old_key, new_key=new_key)
            _warnings.warn(msg, DeprecationWarning)
        return new_key

    def __setitem__(self, key, value):
        new_key = self._get_new_key(key)
        return super().__setitem__(new_key, value)

    def __getitem__(self, key):
        new_key = self._get_new_key(key)
        value = super().__getitem__(new_key)
        return value

    def __setattr__(self, key, value):
        if key == "data":
            return super().__setattr__(key, value)

        self.__setitem__(key, value)

    def __getattr__(self, key):
        if key == "data":
            return self.data

        try:
            value = self.__getitem__(key)
        except KeyError as e:
            msg = "'{type}' object has no attribute '{attr}'".format(type=type(self), attr=key)
            raise AttributeError(msg) from e
        return value

    def to_dict(self) -> dict[str, Any]:
        """
        Converts an object to a dict
        :return: A dict representation of the object
        """
        data = {
            key: value
            for key, value_obj in self.items()
            for value in [value_obj.to_dict() if hasattr(value_obj, "to_dict") else value_obj]
        }
        data.update({key: data.get(value) for key, value in self.__class__._DEPRECATED_TO_NEW_MEMBERS.items()})
        return data

    @classmethod
    def from_dict(cls: type[TDatafySubclass], data: dict[str, Any]) -> TDatafySubclass:
        """
        :param data: A dict representation of an object
        :return: An object
        """
        instance = cls(**data.copy())
        return instance


class AuthenticationInformation(_Datafy):
    """
    Class that holds information about the authentication
    """

    def __init__(
        self,
        auth_class_ref: Optional[str] = None,
        timestamp: Optional[str] = None,
        issuer: Optional[str] = None,
        authority: Optional[Any] = None,
        *args,
        **kwargs,
    ):
        """
        Initiate the data carrier

        :param auth_class_ref: What method that was used for the authentication
        :param timestamp: Time when the authentication was done
        :param issuer: Where the authentication was done
        """
        super().__init__(self, *args, **kwargs)
        self.auth_class_ref = auth_class_ref
        self.timestamp = timestamp
        self.issuer = issuer
        self.authority = authority


class InternalData(_Datafy):
    """
    A base class for the data carriers between frontends/backends
    """

    def __init__(
        self,
        auth_info: Optional[AuthenticationInformation] = None,
        requester: Optional[str] = None,
        requester_name: Optional[list[Mapping[str, Any]]] = None,
        subject_id: Optional[str] = None,
        subject_type: Optional[str] = None,
        attributes: Optional[dict[str, Any]] = None,
        *args,
        **kwargs,
    ):
        """
        :param auth_info:
        :param requester: identifier of the requester
        :param requester_name:
        :param subject_id:
        :param subject_type:
        :param attributes:
        """
        super().__init__(self, *args, **kwargs)
        self.auth_info = (
            auth_info
            if isinstance(auth_info, AuthenticationInformation)
            else AuthenticationInformation(**(auth_info or {}))
        )
        self.requester = requester
        self.requester_name = requester_name if requester_name is not None else [{"text": requester, "lang": "en"}]
        self.subject_id = subject_id
        self.subject_type = subject_type
        self.attributes = attributes if attributes is not None else {}
