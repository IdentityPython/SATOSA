"""Internal data representation for SAML/OAuth/OpenID connect."""


import warnings as _warnings
from collections import UserDict


class _Datafy(UserDict):
    _DEPRECATED_TO_NEW_MEMBERS = {}

    def _get_new_key(self, old_key):
        new_key = self.__class__._DEPRECATED_TO_NEW_MEMBERS.get(old_key, old_key)
        is_key_deprecated = old_key != new_key
        if is_key_deprecated:
            msg = "'{old_key}' is deprecated; use '{new_key}' instead.".format(
                old_key=old_key, new_key=new_key
            )
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

        if not key.startswith("_"):
            msg = " ".join(
                [
                    "Setting attributes on {cls} is deprecated;",
                    "use the dict interface instead:",
                    "Replace 'object.{key} = {value}'",
                    "with 'object[\"{key}\"] = {value}'",
                ]
            ).format(cls=self.__class__, key=key, value=value)
            _warnings.warn(msg, DeprecationWarning)

        self.__setitem__(key, value)

    def __getattr__(self, key):
        if key == "data":
            return self.data

        if not key.startswith("_"):
            msg = " ".join(
                [
                    "Getting attributes from {cls} is deprecated;",
                    "use the dict interface instead:",
                    "Replace 'object.{key}'",
                    "with 'object.get(\"{key}\")'",
                ]
            ).format(cls=self.__class__, key=key)
            _warnings.warn(msg, DeprecationWarning)

        try:
            value = self.__getitem__(key)
        except KeyError as e:
            msg = "'{type}' object has no attribute '{attr}'".format(
                type=type(self), attr=key
            )
            raise AttributeError(msg) from e
        return value

    def to_dict(self):
        """
        Converts an object to a dict
        :rtype: dict[str, str]
        :return: A dict representation of the object
        """
        data = {
            key: value
            for key, value_obj in self.items()
            for value in [
                value_obj.to_dict() if hasattr(value_obj, "to_dict") else value_obj
            ]
        }
        data.update(
            {
                key: data.get(value)
                for key, value in self.__class__._DEPRECATED_TO_NEW_MEMBERS.items()
            }
        )
        return data

    @classmethod
    def from_dict(cls, data):
        """
        :type data: dict[str, str]
        :rtype: satosa.internal.AuthenticationInformation
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
        self, auth_class_ref=None, timestamp=None, issuer=None, *args, **kwargs
    ):
        """
        Initiate the data carrier

        :type auth_class_ref: str
        :type timestamp: str
        :type issuer: str

        :param auth_class_ref: What method that was used for the authentication
        :param timestamp: Time when the authentication was done
        :param issuer: Where the authentication was done
        """
        super().__init__(self, *args, **kwargs)
        self.update(
            {"auth_class_ref": auth_class_ref, "timestamp": timestamp, "issuer": issuer}
        )


class InternalData(_Datafy):
    """
    A base class for the data carriers between frontends/backends
    """

    _DEPRECATED_TO_NEW_MEMBERS = {
        "name_id": "subject_id",
        "user_id": "subject_id",
        "user_id_hash_type": "subject_type",
        "approved_attributes": "attributes",
    }

    def __init__(
        self,
        auth_info=None,
        requester=None,
        requester_name=None,
        subject_id=None,
        subject_type=None,
        attributes=None,
        user_id=None,
        user_id_hash_type=None,
        name_id=None,
        approved_attributes=None,
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
        :param user_id:
        :param user_id_hash_type:
        :param name_id:
        :param approved_attributes:

        :type auth_info: AuthenticationInformation
        :type requester: str
        :type requester_name:
        :type subject_id: str
        :type subject_type: str
        :type attributes: dict
        :type user_id: str
        :type user_id_hash_type: str
        :type name_id: str
        :type approved_attributes: dict
        """
        super().__init__(self, *args, **kwargs)
        self.update(
            {
                "auth_info": (
                    auth_info
                    if isinstance(auth_info, AuthenticationInformation)
                    else AuthenticationInformation(**(auth_info or {}))
                ),
                "requester": requester,
                "requester_name": (
                    requester_name
                    if requester_name is not None
                    else [{"text": requester, "lang": "en"}]
                ),
                "subject_id": (
                    subject_id
                    if subject_id is not None
                    else user_id
                    if user_id is not None
                    else name_id
                    if name_id is not None
                    else None
                ),
                "subject_type": (
                    subject_type
                    if subject_type is not None
                    else user_id_hash_type
                    if user_id_hash_type is not None
                    else None
                ),
                "attributes": (
                    attributes
                    if attributes is not None
                    else approved_attributes
                    if approved_attributes is not None
                    else {}
                ),
            }
        )
