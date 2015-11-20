"""
The module contains internal data representation in SATOSA and general converteras that can be used
for converting from SAML/OAuth/OpenID connect to the internal representation.
"""
import datetime
from enum import Enum
import hashlib
import json

__author__ = 'haho0032'


class DataConverter(object):
    """
    Converts between internal and external data format
    """

    def __init__(self, internal_attributes):
        """
        :type internal_attributes: dict[str, dict[str, dict[str, str]]]
        :param internal_attributes: A map of how to convert the attributes
        (dict[internal_name, dict[external_type, external_name]])
        """
        self.to_internal_attributes = {}
        self.to_internal_attributes_lower = {}
        self.separator = internal_attributes["separator"]
        self.from_internal_attributes = internal_attributes["attributes"]
        for internal_key in self.from_internal_attributes:
            for tmp_type in self.from_internal_attributes[internal_key]:
                if tmp_type not in self.to_internal_attributes:
                    self.to_internal_attributes[tmp_type] = {}
                    self.to_internal_attributes_lower[tmp_type] = {}
                for external_key in self.from_internal_attributes[internal_key][tmp_type]:
                    self.to_internal_attributes[tmp_type][external_key] = internal_key
                    self.to_internal_attributes_lower[tmp_type][external_key.lower()] = internal_key

    def to_internal_filter(self, external_type, external_keys, case_insensitive=False):
        """
        Converts attribute names from external "type" to internal

        :type external_type: str
        :type external_keys: list[str]
        :type case_insensitive: bool
        :rtype: list[str]

        :param external_type: From which external type to convert (ex: oidc, saml, ...)
        :param external_keys: A list of attribute names
        :param case_insensitive: Create a case insensitive filter
        :return: A list of attribute names in the internal format
        """
        internal_keys = []
        for external_key in external_keys:
            if external_key in self.to_internal_attributes[external_type] or \
                    (case_insensitive and external_key in
                        self.to_internal_attributes_lower[external_type]):
                if case_insensitive:
                    internal_key = self.to_internal_attributes_lower[external_type][external_key]
                else:
                    internal_key = self.to_internal_attributes[external_type][external_key]
                if internal_key not in internal_keys:
                    internal_keys.append(internal_key)
        return internal_keys

    def _get_attr_value_key(self, my_key, my_dict):
        tmp_attributes = {}
        for tmp_key in my_dict:
            new_key = "%s%s%s" % (my_key, self.separator, tmp_key)
            if isinstance(my_dict[tmp_key], dict):
                tmp_attributes.update(self._get_attr_value_key(new_key, my_dict[tmp_key]))
            else:
                tmp_attributes[new_key] = my_dict[tmp_key]
        return tmp_attributes

    def to_internal(self, external_type, external_dict):
        """
        Converts the external data from "type" to internal

        :type external_type: str
        :type external_dict: dict[str, str]
        :rtype: dict[str, str]

        :param external_type: From which external type to convert (ex: oidc, saml, ...)
        :param external_dict: Attributes in the external format
        :return: Attributes in the internal format
        """
        internal_dict = {}
        for external_key in external_dict.keys():
            if isinstance(external_dict[external_key], dict):
                if external_key in self.to_internal_attributes[external_type]:
                    internal_key = self.to_internal_attributes[external_type][external_key]
                    if internal_key not in internal_dict:
                        internal_dict[internal_key] = []
                    internal_dict[internal_key].append(json.dumps(external_dict[external_key]))
                else:
                    internal_dict.update(
                        self.to_internal(external_type,
                                         self._get_attr_value_key(external_key,
                                                                  external_dict[external_key])))
            elif external_key in self.to_internal_attributes[external_type]:
                internal_key = self.to_internal_attributes[external_type][external_key]
                if internal_key not in internal_dict:
                    internal_dict[internal_key] = []
                if isinstance(external_dict[external_key], list):
                    internal_dict[internal_key] += external_dict[external_key]
                else:
                    internal_dict[internal_key].append(external_dict[external_key])
        return internal_dict

    def from_internal(self, external_type, internal_dict, attr_list=True, external_keys=None):
        # TODO doc about external_keys
        """
        Converts the internal data to "type"

        :type external_type: str
        :type internal_dict: dict[str, str]
        :type attr_list: bool
        :type external_keys:
        :rtype: dict[str, str]

        :param external_type: To which external type to convert (ex: oidc, saml, ...)
        :param attr_list: Should all attribute values be in a list
        :param external_keys:
        :return: Attributes in the "type" format
        """
        external_dict = {}
        for internal_key in internal_dict:
            if internal_key in self.from_internal_attributes:
                _external_keys = self.from_internal_attributes[internal_key][external_type]
                if _external_keys:
                    _external_key = None
                    if external_keys:
                        for _external_key in _external_keys:
                            if _external_key in external_keys:
                                break
                    if _external_key is None:
                        _external_key = _external_keys[0]
                    _external_dict = external_dict
                    if self.separator in _external_key:
                        _tmp_keys = _external_key.split(self.separator)
                        for _tmp_key in _tmp_keys:
                            if _tmp_key not in _external_dict:
                                _external_dict[_tmp_key] = {}
                            _external_dict = _external_dict[_tmp_key]
                    if attr_list:
                        _external_dict[_external_key] = internal_dict[internal_key]
                    else:
                        if internal_dict[internal_key]:
                            _external_dict[_external_key] = internal_dict[internal_key][0]
        return external_dict


class UserIdHashType(Enum):
    """
    All different user id hash types
    """
    transient = 1
    persistent = 2
    pairwise = 2
    public = 3


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
        state.add(UserIdHasher.STATE_KEY, internal_request.requestor)

    @staticmethod
    def set_id(salt, internal_response, state):
        """
        Sets a user id to the internal_response, in the format specified by the internal response

        :type salt: str
        :type internal_response: satosa.internal_data.InternalResponse
        :type state: satosa.state.State
        :rtype: internal_response: satosa.internal_data.InternalResponse

        :param salt: A salt string for the ID hashing
        :param internal_response:  The authentication response
        :param state: The current state
        :return: the internal_response containing the hashed user ID
        """
        requestor = state.get(UserIdHasher.STATE_KEY)
        user_id = internal_response.user_id
        user_id_hash_type = internal_response.user_id_hash_type

        if user_id_hash_type == UserIdHashType.transient:
            timestamp = datetime.datetime.now().time()
            user_id = "{req}{time}{id}".format(req=requestor, time=timestamp, id=user_id)
        elif user_id_hash_type == UserIdHashType.persistent:
            user_id = "{req}{id}".format(req=requestor, id=user_id)
        elif user_id_hash_type == UserIdHashType.pairwise:
            user_id = "{req}{id}".format(req=requestor, id=user_id)
        elif user_id_hash_type == UserIdHashType.public:
            user_id = "{id}".format(id=user_id)
        else:
            raise ValueError("Unknown id hash type: '{}'".format(user_id_hash_type))

        user_id += salt
        internal_response.user_id = hashlib.sha256(user_id.encode("utf-8")).hexdigest()

        return internal_response


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
        # TODO Should the auth_class_ref be replaced by a LOA attribute?
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
                "auth_class_ref": self.auth_class_ref, }


class InternalData(object):
    """
    A base class for the data carriers between frontends/backends
    """

    def __init__(self, user_id_hash_type):
        self.user_id_hash_type = user_id_hash_type


class InternalRequest(InternalData):
    """
    Internal request for SATOSA.
    """
    def __init__(self, user_id_hash_type, requestor):
        """

        :param user_id_hash_type:
        :param requestor: identifier of the requestor

        :type user_id_hash_type: UserIdHashType
        :type requestor: str
        """
        super(InternalRequest, self).__init__(user_id_hash_type)
        self.requestor = requestor
        self._attribute_filter = []

    def add_filter(self, filter_attr):
        """
        Set a list of attributes that will pass through the attribute filter

        :type filter_attr: list[str]

        :param filter_attr: a list of attributes that can be sent to the requestor
        """
        self._attribute_filter = filter_attr

    def get_filter(self):
        """
        A list with all approved attributes.
        :rtype: list[str]
        :return: Attribute filter
        """
        return self._attribute_filter


class InternalResponse(InternalData):
    """
    Holds internal representation of service related data.

    :type _user_id: str
    :type _attributes: dict[str, str]
    :type user_id_hash_type: UserIdHashType
    :type auth_info: AuthenticationInformation
    """

    def __init__(self, user_id_hash_type, auth_info=None):
        super(InternalResponse, self).__init__(user_id_hash_type)
        self._user_id = None
        # This dict is a data carrier between frontend and backend modules.
        self._attributes = {}
        self.auth_info = auth_info

    def get_attributes(self):
        """
        Returns all user attributes received in the authentication

        :rtype: dict[str, str]

        :return: all attributes
        """
        return self._attributes

    def add_attributes(self, attr_dict):
        """
        Add user attributes converted to the internal format

        :type attr_dict: dict[str, str]
        :param attr_dict: A dictionary containing user attributes converted to the internal format
        """
        self._attributes = attr_dict

    @property
    def user_id(self):
        """
        Get the user identification.

        :rtype: str

        :return: User identification.
        """
        return self._user_id

    @user_id.setter
    def user_id(self, user_id):
        """
        Set the user identification.
        :type user_id: str
        :param user_id: User identification.
        """
        if not user_id:
            raise ValueError("user_id can't be set to None")
        elif user_id.startswith('/'):
            raise ValueError("user_id can't start with '/'")
        self._user_id = user_id

    @staticmethod
    def from_dict(int_resp_dict):
        """
        :type int_resp_dict: dict[str, dict[str, str] | str]
        :rtype: satosa.internal_data.InternalResponse
        :param int_resp_dict: A dict representation of an InternalResponse object
        :return: An InternalResponse object
        """
        auth_info = AuthenticationInformation.from_dict(int_resp_dict["auth_info"])
        internal_response = InternalResponse(getattr(UserIdHashType, int_resp_dict["hash_type"]),
                                             auth_info=auth_info)
        internal_response._attributes = int_resp_dict["attr"]
        internal_response.user_id = int_resp_dict["usr_id"]
        return internal_response

    def to_dict(self):
        """
        Converts an InternalResponse object to a dict
        :rtype: dict[str, dict[str, str] | str]
        :return: A dict representation of the object
        """
        return {"usr_id": self.user_id,
                "attr": self.get_attributes(),
                "hash_type": self.user_id_hash_type.name,
                "auth_info": self.auth_info.to_dict()}
