"""Internal data representation for SAML/OAuth/OpenID connect."""


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
    ):
        """
        :param auth_info:
        :param requester: identifier of the requester
        :param requester_name:
        :param subject_id:
        :param subject_type:
        :param attributes:

        :type auth_info: AuthenticationInformation
        :type requester: str
        :type requester_name:
        :type subject_id: str
        :type subject_type: str
        :type attributes: dict
        """
        self.auth_info = auth_info or AuthenticationInformation()
        self.requester = requester
        self.requester_name = requester_name or [
            {"text": requester, "lang": "en"}
        ]
        self.subject_id = subject_id
        self.subject_type = subject_type
        self.attributes = {} if attributes is None else attributes

    def to_dict(self):
        """
        Converts an InternalData object to a dict
        :rtype: dict[str, str]
        :return: A dict representation of the object
        """
        return {
            "auth_info": self.auth_info.to_dict(),
            "requester": self.requester,
            "requester_name": self.requester_name,
            "attributes": self.attributes,
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
        }

    @classmethod
    def from_dict(cls, data):
        """
        :type data: dict[str, str]
        :rtype: satosa.internal.InternalData
        :param data: A dict representation of an InternalData object
        :return: An InternalData object
        """
        auth_info = data.get("auth_info", AuthenticationInformation())
        return cls(
            auth_info=AuthenticationInformation.from_dict(auth_info),
            requester=data.get("requester"),
            requester_name=data.get("requester_name"),
            subject_id=data.get("subject_id"),
            subject_type=data.get("subject_type"),
            attributes=data.get("attributes"),
        )

    def __repr__(self):
        return str(self.to_dict())
