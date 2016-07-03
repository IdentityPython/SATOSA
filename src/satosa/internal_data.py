"""
The module contains internal data representation in SATOSA and general converteras that can be used
for converting from SAML/OAuth/OpenID connect to the internal representation.
"""
import datetime
import hashlib
import json
from collections import defaultdict
from enum import Enum
from itertools import chain

from mako.template import Template


class DataConverter(object):
    """
    Converts between internal and external data format
    """

    def __init__(self, internal_attributes):
        """
        :type internal_attributes: dict[str, dict[str, dict[str, str]]]
        :param internal_attributes: A map of how to convert the attributes
        (dict[internal_name, dict[attribute_profile, external_name]])
        """
        self.separator = "."  # separator for nested attribute values, e.g. address.street_address
        self.multivalue_separator = ";"  # separates multiple values, e.g. when using templates
        self.from_internal_attributes = internal_attributes["attributes"]
        self.template_attributes = internal_attributes.get("template_attributes", None)

        self.to_internal_attributes = defaultdict(dict)
        for internal_attribute_name, mappings in self.from_internal_attributes.items():
            for profile, external_attribute_names in mappings.items():
                for external_attribute_name in external_attribute_names:
                    self.to_internal_attributes[profile][external_attribute_name] = internal_attribute_name

    def to_internal_filter(self, attribute_profile, external_attribute_names):
        """
        Converts attribute names from external "type" to internal

        :type attribute_profile: str
        :type external_attribute_names: list[str]
        :type case_insensitive: bool
        :rtype: list[str]

        :param attribute_profile: From which external type to convert (ex: oidc, saml, ...)
        :param external_attribute_names: A list of attribute names
        :param case_insensitive: Create a case insensitive filter
        :return: A list of attribute names in the internal format
        """
        try:
            profile_mapping = self.to_internal_attributes[attribute_profile]
        except KeyError:
            # no attributes since the given profile is not configured
            return []

        internal_attribute_names = set()  # use set to ensure only unique values
        for external_attribute_name in external_attribute_names:
            try:
                internal_attribute_name = profile_mapping[external_attribute_name]
                internal_attribute_names.add(internal_attribute_name)
            except KeyError:
                pass

        return list(internal_attribute_names)

    def to_internal(self, attribute_profile, external_dict):
        """
        Converts the external data from "type" to internal

        :type attribute_profile: str
        :type external_dict: dict[str, str]
        :rtype: dict[str, str]

        :param attribute_profile: From which external type to convert (ex: oidc, saml, ...)
        :param external_dict: Attributes in the external format
        :return: Attributes in the internal format
        """
        internal_dict = {}

        for internal_attribute_name, mapping in self.from_internal_attributes.items():
            if attribute_profile not in mapping:
                # skip this internal attribute if we have no mapping in the specified profile
                continue

            external_attribute_name = mapping[attribute_profile]
            attribute_values = self._collate_attribute_values_by_priority_order(external_attribute_name,
                                                                                external_dict)
            if attribute_values:  # Only insert key if it has some values
                internal_dict[internal_attribute_name] = attribute_values

        internal_dict = self._handle_template_attributes(attribute_profile, internal_dict)
        return internal_dict

    def _collate_attribute_values_by_priority_order(self, attribute_names, data):
        result = []
        for attr_name in attribute_names:
            attr_val = self._get_nested_attribute_value(attr_name, data)

            if isinstance(attr_val, list):
                result.extend(attr_val)
            elif attr_val:
                result.append(attr_val)

        return result

    def _render_attribute_template(self, template, data):
        t = Template(template, cache_enabled=True, imports=["from satosa.util import scope"])
        try:
            return t.render(**data).split(self.multivalue_separator)
        except (NameError, TypeError) as e:
            return []

    def _handle_template_attributes(self, attribute_profile, internal_dict):
        if not self.template_attributes:
            return internal_dict

        for internal_attribute_name, mapping in self.template_attributes.items():
            if attribute_profile not in mapping:
                # skip this internal attribute if we have no mapping in the specified profile
                continue

            external_attribute_name = mapping[attribute_profile]
            templates = [t for t in external_attribute_name if "$" in t]  # these looks like templates...
            template_attribute_values = [self._render_attribute_template(template, internal_dict) for template in
                                         templates]
            flattened_attribute_values = list(chain.from_iterable(template_attribute_values))
            attribute_values = flattened_attribute_values or internal_dict.get(internal_attribute_name, None)
            if attribute_values:  # only insert key if it has some values
                internal_dict[internal_attribute_name] = attribute_values

        return internal_dict

    def _get_nested_attribute_value(self, nested_key, data):
        keys = nested_key.split(self.separator)

        d = data
        for key in keys:
            d = d.get(key)
            if d is None:
                return None
        return d

    def _create_nested_attribute_value(self, nested_attribute_names, value):
        if len(nested_attribute_names) == 1:
            # we've reached the inner-most attribute name, set value here
            return {nested_attribute_names[0]: value}

        # keep digging further into the nested attribute names
        child_dict = self._create_nested_attribute_value(nested_attribute_names[1:], value)
        return {nested_attribute_names[0]: child_dict}

    def from_internal(self, attribute_profile, internal_dict):
        """
        Converts the internal data to "type"

        :type attribute_profile: str
        :type internal_dict: dict[str, str]
        :rtype: dict[str, str]

        :param attribute_profile: To which external type to convert (ex: oidc, saml, ...)
        :param internal_dict: attributes to map
        :return: attribute values and names in the specified "profile"
        """
        external_dict = {}
        for internal_attribute_name in internal_dict:
            if attribute_profile not in self.from_internal_attributes[internal_attribute_name]:
                # skip this internal attribute if we have no mapping in the specified profile
                continue

            external_attribute_names = self.from_internal_attributes[internal_attribute_name][attribute_profile]
            # select the first attribute name
            external_attribute_name = external_attribute_names[0]

            if self.separator in external_attribute_name:
                nested_attribute_names = external_attribute_name.split(self.separator)
                nested_dict = self._create_nested_attribute_value(nested_attribute_names[1:],
                                                                  internal_dict[internal_attribute_name])
                external_dict[nested_attribute_names[0]] = nested_dict
            else:
                external_dict[external_attribute_name] = internal_dict[internal_attribute_name]

        return external_dict


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
        v = json.dumps(value)
        return hashlib.sha512((v + salt).encode("utf-8")).hexdigest()

    @staticmethod
    def hash_type(state):
        state_data = state[UserIdHasher.STATE_KEY]
        hash_type = UserIdHashType.from_string(state_data["hash_type"])
        return hash_type

    @staticmethod
    def hash_id(salt, user_id, requestor, state):
        """
        Sets a user id to the internal_response, in the format specified by the internal response

        :type salt: str
        :type user_id: str
        :type requestor: str
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
            user_id = "{req}{time}{id}".format(req=requestor, time=timestamp, id=user_id)
        elif hash_type == UserIdHashType.persistent or hash_type == UserIdHashType.pairwise:
            user_id = "{req}{id}".format(req=requestor, id=user_id)
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

    def __init__(self, user_id_hash_type, requestor, requester_name=None):
        """

        :param user_id_hash_type:
        :param requestor: identifier of the requestor

        :type user_id_hash_type: UserIdHashType
        :type requestor: str
        """
        self.user_id_hash_type = user_id_hash_type
        self.requestor = requestor
        if requester_name:  # TODO do you need to validate this?
            self.requester_name = requester_name
        else:
            self.requester_name = [{"text": requestor, "lang": "en"}]
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
        self.to_requestor = None

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
        internal_response.to_requestor = int_resp_dict["to"]
        return internal_response

    def to_dict(self):
        """
        Converts an InternalResponse object to a dict
        :rtype: dict[str, dict[str, str] | str]
        :return: A dict representation of the object
        """
        _dict = {"usr_id": self.user_id,
                 "attr": self.attributes,
                 "to": self.to_requestor,
                 "auth_info": self.auth_info.to_dict()}
        if self.user_id_hash_type:
            _dict["hash_type"] = self.user_id_hash_type.name
        return _dict
