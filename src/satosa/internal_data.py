"""
The module contains internal data representation in SATOSA and general converteras that can be used
for converting from SAML/OAuth/OpenID connect to the internal representation.
"""
import datetime
import hashlib
from enum import Enum


class UserIdHashType(Enum):
    """
    All different user id hash types
    """
    transient = 1
    persistent = 2
    pairwise = 3
    public = 4

    @classmethod
    def from_string(cls, str):
        try:
            return getattr(cls, str)
        except AttributeError:
            raise ValueError("Unknown hash type '{}'".format(str))


class UserIdHasher(object):
    """
    Class for creating different user id types
    """
    STATE_KEY = "IDHASHER"

    @staticmethod
    def save_state(internal_request, state):
        """
        Saves all necessary information needed by the UserIdHasher

        :type internal_request: satosa.internal_data.InternalRequest

        :param internal_request: The request
        :param state: The current state
        """
        state_data = {
            "hash_type": internal_request.user_id_hash_type.name
        }
        state[UserIdHasher.STATE_KEY] = state_data

    @staticmethod
    def hash_data(salt, value):
        """
        Hashes a value together with a salt.
        :type salt: str
        :type value: str
        :param salt: hash salt
        :param value: value to hash together with the salt
        :return: hash value (SHA512)
        """
        return hashlib.sha512((value + salt).encode("utf-8")).hexdigest()

    @staticmethod
    def hash_type(state):
        state_data = state[UserIdHasher.STATE_KEY]
        hash_type = UserIdHashType.from_string(state_data["hash_type"])
        return hash_type

    @staticmethod
    def hash_id(salt, user_id, requester, state):
        """
        Sets a user id to the internal_response, in the format specified by the internal response

        :type salt: str
        :type user_id: str
        :type requester: str
        :type state: satosa.state.State
        :rtype: str

        :param salt: A salt string for the ID hashing
        :param user_id: the user id
        :param user_id_hash_type: Hashing type
        :param state: The current state
        :return: the internal_response containing the hashed user ID
        """
        hash_type = UserIdHasher.hash_type(state)
        if hash_type == UserIdHashType.transient:
            timestamp = datetime.datetime.now().time()
            user_id = "{req}{time}{id}".format(req=requester, time=timestamp, id=user_id)
        elif hash_type == UserIdHashType.persistent or hash_type == UserIdHashType.pairwise:
            user_id = "{req}{id}".format(req=requester, id=user_id)
        elif hash_type == UserIdHashType.public:
            user_id = "{id}".format(id=user_id)
        else:
            raise ValueError("Unknown hash type: '{}'".format(hash_type))

        return UserIdHasher.hash_data(salt, user_id)


class AuthenticationInformation(object):
    """
    Class that holds information about the authentication
    """

    def __init__(self, auth_class_ref, timestamp, issuer):
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

    @staticmethod
    def from_dict(auth_info_dict):
        """
        :type auth_info_dict: dict[str, str]
        :rtype: satosa.internal_data.AuthenticationInformation
        :param auth_info_dict: A dict representation of an AuthenticationInformation object
        :return: An AuthenticationInformation object
        """
        return AuthenticationInformation(auth_info_dict["auth_class_ref"],
                                         auth_info_dict["timestamp"],
                                         auth_info_dict["issuer"])

    def to_dict(self):
        """
        Converts an AuthenticationInformation object to a dict
        :rtype: dict[str, str]
        :return: A dict representation of the object
        """
        return {"issuer": self.issuer,
                "timestamp": self.timestamp,
                "auth_class_ref": self.auth_class_ref,}


class InternalData(object):
    """
    A base class for the data carriers between frontends/backends
    """
    pass


class InternalRequest(InternalData):
    """
    Internal request for SATOSA.
    """

    def __init__(self, user_id_hash_type, requester, requester_name=None):
        """

        :param user_id_hash_type:
        :param requester: identifier of the requester

        :type user_id_hash_type: UserIdHashType
        :type requester: str
        """
        self.user_id_hash_type = user_id_hash_type
        self.requester = requester
        if requester_name:
            self.requester_name = requester_name
        else:
            self.requester_name = [{"text": requester, "lang": "en"}]
        self.approved_attributes = None


class InternalResponse(InternalData):
    """
    Holds internal representation of service related data.

    :type _user_id: str
    :type attributes: dict[str, str]
    :type user_id_hash_type: UserIdHashType
    :type auth_info: AuthenticationInformation
    """

    def __init__(self, auth_info=None):
        super().__init__()
        self.user_id = None
        # This dict is a data carrier between frontend and backend modules.
        self.attributes = {}
        self.auth_info = auth_info
        self.user_id_hash_type = None
        self.requester = None

    @staticmethod
    def from_dict(int_resp_dict):
        """
        :type int_resp_dict: dict[str, dict[str, str] | str]
        :rtype: satosa.internal_data.InternalResponse
        :param int_resp_dict: A dict representation of an InternalResponse object
        :return: An InternalResponse object
        """
        auth_info = AuthenticationInformation.from_dict(int_resp_dict["auth_info"])
        internal_response = InternalResponse(auth_info=auth_info)
        if "hash_type" in int_resp_dict:
            internal_response.user_id_hash_type = UserIdHashType.from_string(int_resp_dict["hash_type"])
        internal_response.attributes = int_resp_dict["attr"]
        internal_response.user_id = int_resp_dict["usr_id"]
        internal_response.requester = int_resp_dict["to"]
        return internal_response

    def to_dict(self):
        """
        Converts an InternalResponse object to a dict
        :rtype: dict[str, dict[str, str] | str]
        :return: A dict representation of the object
        """
        _dict = {"usr_id": self.user_id,
                 "attr": self.attributes,
                 "to": self.requester,
                 "auth_info": self.auth_info.to_dict()}
        if self.user_id_hash_type:
            _dict["hash_type"] = self.user_id_hash_type.name
        return _dict
