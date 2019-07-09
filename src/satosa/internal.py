"""Internal data representation for SAML/OAuth/OpenID connect."""


import warnings as _warnings


class AuthenticationInformation(object):
    """
    Class that holds information about the authentication
    """

    def __init__(self, auth_class_ref=None, timestamp=None, issuer=None):
        """
        Initiate the data carrier

        :type auth_class_ref: str
        :type timestamp: str
        :type issuer: str

        :param auth_class_ref: What method that was used for the authentication
        :param timestamp: Time when the authentication was done
        :param issuer: Where the authentication was done
        """
        self.auth_class_ref = auth_class_ref
        self.timestamp = timestamp
        self.issuer = issuer

    def to_dict(self):
        """
        Converts an AuthenticationInformation object to a dict
        :rtype: dict[str, str]
        :return: A dict representation of the object
        """
        return {
            "auth_class_ref": self.auth_class_ref,
            "timestamp": self.timestamp,
            "issuer": self.issuer,
        }

    @classmethod
    def from_dict(cls, data):
        """
        :type data: dict[str, str]
        :rtype: satosa.internal.AuthenticationInformation
        :param data: A dict representation of an AuthenticationInformation object
        :return: An AuthenticationInformation object
        """
        return cls(
            auth_class_ref=data.get("auth_class_ref"),
            timestamp=data.get("timestamp"),
            issuer=data.get("issuer"),
        )

    def __repr__(self):
        return str(self.to_dict())


class InternalData(object):
    """
    A base class for the data carriers between frontends/backends
    """

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
        self.auth_info = auth_info or AuthenticationInformation()
        self.requester = requester
        self.requester_name = (
            requester_name
            if requester_name is not None
            else [
                {"text": requester, "lang": "en"}
            ]
        )
        self.subject_id = (
            subject_id
            if subject_id is not None
            else user_id
            if user_id is not None
            else name_id
            if name_id is not None
            else None
        )
        self.subject_type = (
            subject_type
            if subject_type is not None
            else user_id_hash_type
            if user_id_hash_type is not None
            else None
        )
        self.attributes = (
            attributes
            if attributes is not None
            else approved_attributes
            if approved_attributes is not None
            else {}
        )

    def to_dict(self):
        """
        Converts an InternalData object to a dict
        :rtype: dict[str, str]
        :return: A dict representation of the object
        """
        data = {
            "auth_info": self.auth_info.to_dict(),
            "requester": self.requester,
            "requester_name": self.requester_name,
            "attributes": self.attributes,
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
        }
        data.update(
            {
                "user_id": self.subject_id,
                "hash_type": self.subject_type,
                "name_id": self.subject_id,
                "approved_attributes": self.attributes,
            }
        )
        return data

    @classmethod
    def from_dict(cls, data):
        """
        :type data: dict[str, str]
        :rtype: satosa.internal.InternalData
        :param data: A dict representation of an InternalData object
        :return: An InternalData object
        """
        auth_info = AuthenticationInformation.from_dict(
            data.get("auth_info", {})
        )
        instance = cls(
            auth_info=auth_info,
            requester=data.get("requester"),
            requester_name=data.get("requester_name"),
            subject_id=data.get("subject_id"),
            subject_type=data.get("subject_type"),
            attributes=data.get("attributes"),
            user_id=data.get("user_id"),
            user_id_hash_type=data.get("hash_type"),
            name_id=data.get("name_id"),
            approved_attributes=data.get("approved_attributes"),
        )
        return instance

    @property
    def user_id(self):
        msg = "user_id is deprecated; use subject_id instead."
        _warnings.warn(msg, DeprecationWarning)
        return self.subject_id

    @user_id.setter
    def user_id(self, value):
        msg = "user_id is deprecated; use subject_id instead."
        _warnings.warn(msg, DeprecationWarning)
        self.subject_id = value

    @property
    def user_id_hash_type(self):
        msg = "user_id_hash_type is deprecated; use subject_type instead."
        _warnings.warn(msg, DeprecationWarning)
        return self.subject_type

    @user_id_hash_type.setter
    def user_id_hash_type(self, value):
        msg = "user_id_hash_type is deprecated; use subject_type instead."
        _warnings.warn(msg, DeprecationWarning)
        self.subject_type = value

    @property
    def approved_attributes(self):
        msg = "approved_attributes is deprecated; use attributes instead."
        _warnings.warn(msg, DeprecationWarning)
        return self.attributes

    @approved_attributes.setter
    def approved_attributes(self, value):
        msg = "approved_attributes is deprecated; use attributes instead."
        _warnings.warn(msg, DeprecationWarning)
        self.attributes = value

    @property
    def name_id(self):
        msg = "name_id is deprecated; use subject_id instead."
        _warnings.warn(msg, DeprecationWarning)
        return self.subject_id

    @name_id.setter
    def name_id(self, value):
        msg = "name_id is deprecated; use subject_id instead."
        _warnings.warn(msg, DeprecationWarning)
        self.subject_id = value

    def __repr__(self):
        return str(self.to_dict())
